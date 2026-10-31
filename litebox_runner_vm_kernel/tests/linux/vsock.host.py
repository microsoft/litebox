#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Host end of the vsock test: usage `vsock.host.py CID CONSOLE`, or
`vsock.host.py --uds PATH CONSOLE`.

Listens on an ephemeral host port, and holds another without listening, so
connections to it are refused; waits for the guest's `ready` line in the
console output file CONSOLE, then connects to guest CID, port 1024 and 1027,
for the scenarios vsock.c serves, in its order, with a refused connection to a
port nothing listens on after the first. Then sends the two host ports to guest port 1028, and serves
the guest's connections to them, in vsock.c's order; exits 0 if all of them
went as expected.

With `--uds PATH`, the guest is behind a hybrid-vsock bridge at PATH (the
userland broker's `--vsock-uds PATH`) instead of a VM's vsock device: a
connection to the guest's port P is an AF_UNIX connection to PATH, which
writes `CONNECT P\\n` and reads `OK <host port>\\n` (a refused one is closed
instead); the host's port P is the AF_UNIX listener PATH_P, which is fixed
(HYBRID_PORTS), and a refused one is bound without listening. A Unix socket
cannot express everything a vsock one does, so this mode skips:
- the peer address of the guest's connections, which a Unix socket does not
  have: the guest's CID and port are not checked against what it sends;
- SO_VM_SOCKETS_BUFFER_SIZE, which sets the credit a slow reader gives the
  guest: a slow reader only reads slowly, which the stream's own buffer
  bounds.
"""

import atexit
import os
import socket
import sys
import time

PORT = 1024
UNUSED_PORT = 1026
NONBLOCKING_PORT = 1027
HOST_PORTS_PORT = 1028
# As vsock.c's.
BULK = 2 * 1024 * 1024
SLOW = 256 * 1024
CHURN = 40
AFTER_CLOSE = 3
REQUEST = b"request!"
REPLY = 64 * 1024
ACK = b"ack"
QUEUED = b"queued"
REPLIED = b"replied"
FIRST = 128 * 1024
GO = b"go"
LATER = b"later"
BACKPRESSURE = 1024 * 1024
ACCEPT4 = b"accept4"
CLIENT_BULK = 1024 * 1024
# The receive buffer, and the pause between receives, of slow readers.
SLOW_BUFFER = 4096
SLOW_PAUSE = 0.001
# Each step's; the run script's TIMEOUT bounds the whole.
STEP_TIMEOUT = 60
# In the hybrid-vsock mode, the bridge's PATH; else None.
UDS = None
# In the hybrid-vsock mode, the host ports the guest connects to: one
# listening, one refusing.
HYBRID_PORTS = (2000, 2001)


def pattern(length):
    return bytes((i * 7 + i // 4096) & 0xFF for i in range(length))


def wait_ready(console, deadline):
    while time.monotonic() < deadline:
        try:
            with open(console, "rb") as f:
                if b"ready" in f.read().splitlines():
                    return
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    raise TimeoutError("the guest never printed `ready`")


def connect_hybrid(port):
    """Connects to the guest's `port` through the hybrid-vsock bridge."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(STEP_TIMEOUT)
    s.connect(UDS)
    s.sendall(f"CONNECT {port}\n".encode())
    # One byte at a time: what follows the line is the guest's.
    reply = b""
    while not reply.endswith(b"\n"):
        byte = s.recv(1)
        if not byte:
            s.close()
            raise ConnectionResetError(f"the bridge refused the connection to port {port}")
        reply += byte
    if not reply.startswith(b"OK ") or not reply[3:-1].isdigit():
        s.close()
        raise AssertionError(f"the bridge replied {reply!r}")
    return s


def connect(cid, port, slow=False):
    if UDS is not None:
        return connect_hybrid(port)
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(STEP_TIMEOUT)
    if slow:
        # The credit it gives the guest.
        s.setsockopt(socket.AF_VSOCK, socket.SO_VM_SOCKETS_BUFFER_SIZE, SLOW_BUFFER)
    s.connect((cid, port))
    return s


def read_to_eof(s, slow=False):
    chunks = []
    while True:
        if slow:
            time.sleep(SLOW_PAUSE)
        chunk = s.recv(SLOW_BUFFER if slow else 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def read_exactly(s, length, slow=False):
    chunks = []
    while length:
        if slow:
            time.sleep(SLOW_PAUSE)
        chunk = s.recv(min(length, SLOW_BUFFER if slow else 65536))
        if not chunk:
            raise AssertionError(f"EOF with {length} bytes to read")
        chunks.append(chunk)
        length -= len(chunk)
    return b"".join(chunks)


def check_data(received, expected):
    if len(received) != len(expected):
        raise AssertionError(f"received {len(received)} bytes, expected {len(expected)}")
    if received != expected:
        first = next(i for i in range(len(expected)) if received[i] != expected[i])
        raise AssertionError(f"received data differs at byte {first}")


def concurrent(cid):
    sockets = [connect(cid, PORT) for _ in range(2)]
    messages = [f"hello from connection {i}\n".encode() * (i + 1) for i in range(2)]
    # Both open before either sends.
    for s, message in reversed(list(zip(sockets, messages))):
        s.sendall(message)
        s.shutdown(socket.SHUT_WR)
    for s, message in zip(sockets, messages):
        echo = read_to_eof(s)
        if echo != message:
            raise AssertionError(f"echo {echo!r}, expected {message!r}")
        s.close()


def refused(cid):
    try:
        connect(cid, UNUSED_PORT).close()
    except ConnectionResetError:
        return
    raise AssertionError(f"connected to port {UNUSED_PORT}, where nothing listens")


def churn(cid):
    for i in range(CHURN):
        s = connect(cid, PORT)
        kind = i % 3
        if kind == 0:
            message = f"ping {i}".encode()
            s.sendall(message)
            s.shutdown(socket.SHUT_WR)
            expected = message
        elif kind == 1:
            expected = f"hello {i}".encode()
        else:
            s.sendall(f"abort {i}".encode())
            s.close()
            continue
        received = read_to_eof(s)
        if received != expected:
            raise AssertionError(f"connection {i}: {received!r}, expected {expected!r}")
        s.close()


def send_until_broken_pipe(s):
    deadline = time.monotonic() + STEP_TIMEOUT
    while time.monotonic() < deadline:
        try:
            s.send(b"more")
        except BrokenPipeError:
            return
        time.sleep(0.01)
    raise AssertionError("sends after the guest closed did not fail")


def after_close(cid):
    for _ in range(AFTER_CLOSE):
        s = connect(cid, PORT)
        s.sendall(REQUEST)
        # The guest replies and closes meanwhile, while this end does not
        # read: the reply fits in this end's buffer, beyond which, as in
        # Linux, the guest buffers nothing.
        time.sleep(0.2)
        send_until_broken_pipe(s)
        check_data(read_to_eof(s, slow=True), pattern(REPLY))
        s.close()


def bulk(cid, size, slow):
    s = connect(cid, PORT, slow)
    data = pattern(size)
    s.sendall(data)
    check_data(read_to_eof(s, slow), data)
    # The guest waits for this before it ends.
    s.sendall(ACK)
    s.close()


def local_shutdown(cid):
    s = connect(cid, PORT)
    s.sendall(QUEUED)
    reply = read_to_eof(s)
    if reply != REPLIED:
        raise AssertionError(f"reply {reply!r} after the guest shut down receiving")
    s.close()


def nonblocking(cid):
    s = connect(cid, NONBLOCKING_PORT, slow=True)
    s.sendall(pattern(FIRST))
    # The guest finds no more data before this.
    check_data(read_exactly(s, len(GO)), GO)
    s.sendall(LATER)
    check_data(read_exactly(s, BACKPRESSURE, slow=True), pattern(BACKPRESSURE))
    s.sendall(ACK)
    s.close()
    s = connect(cid, NONBLOCKING_PORT)
    s.sendall(ACCEPT4)
    s.shutdown(socket.SHUT_WR)
    echo = read_to_eof(s)
    if echo != ACCEPT4:
        raise AssertionError(f"accept4 echo {echo!r}")
    s.close()


def host_sockets():
    """A listener on an ephemeral host port, and a socket that holds another
    without listening."""
    if UDS is not None:
        return hybrid_host_sockets()
    listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    listener.settimeout(STEP_TIMEOUT)
    listener.bind((socket.VMADDR_CID_ANY, socket.VMADDR_PORT_ANY))
    listener.listen(8)
    refuser = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    refuser.bind((socket.VMADDR_CID_ANY, socket.VMADDR_PORT_ANY))
    return listener, refuser


def hybrid_host_sockets():
    """A listener on PATH_P, and a socket bound to PATH_Q without listening,
    for HYBRID_PORTS P and Q; each path is removed at exit if still its
    socket."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.settimeout(STEP_TIMEOUT)
    bind_hybrid(listener, HYBRID_PORTS[0])
    listener.listen(8)
    refuser = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bind_hybrid(refuser, HYBRID_PORTS[1])
    return listener, refuser


def bind_hybrid(s, port):
    """Binds `s` to PATH_`port`, which is removed at exit if it is still the
    socket bound (by device and inode); best effort, as the check and the
    unlink are two steps."""
    path = f"{UDS}_{port}"
    s.bind(path)
    bound = os.lstat(path)
    identity = (bound.st_dev, bound.st_ino)

    def remove():
        try:
            entry = os.lstat(path)
            if (entry.st_dev, entry.st_ino) == identity:
                os.unlink(path)
        except FileNotFoundError:
            pass

    atexit.register(remove)


def host_ports(listener, refuser):
    """The ports of the host's listener and refuser."""
    if UDS is not None:
        return HYBRID_PORTS
    return (listener.getsockname()[1], refuser.getsockname()[1])


def accept_guest(cid, listener):
    if UDS is not None:
        # A Unix socket's peer has no address: no port to check.
        s, _ = listener.accept()
        s.settimeout(STEP_TIMEOUT)
        return s, None
    s, (peer_cid, peer_port) = listener.accept()
    s.settimeout(STEP_TIMEOUT)
    if peer_cid != cid:
        raise AssertionError(f"a connection from CID {peer_cid}, not {cid}")
    return s, peer_port


def check_name(received, name, peer_port):
    """Checks the guest's `NAME PORT`, its own port, against its peer, if
    known."""
    if peer_port is None:
        name_part, _, port = received.decode(errors="replace").partition(" ")
        if name_part != name or not port.isdigit():
            raise AssertionError(f"{received!r}, expected {name!r} and a port")
        return
    expected = f"{name} {peer_port}".encode()
    if received != expected:
        raise AssertionError(f"{received!r} from port {peer_port}, expected {expected!r}")


def echo_guest(cid, listener, name):
    s, peer_port = accept_guest(cid, listener)
    message = read_to_eof(s)
    check_name(message, name, peer_port)
    s.sendall(message)
    s.close()


def serve_guest(cid, listener, refuser):
    s = connect(cid, HOST_PORTS_PORT)
    ports = host_ports(listener, refuser)
    s.sendall(" ".join(map(str, ports)).encode())
    s.shutdown(socket.SHUT_WR)
    if read_to_eof(s):
        raise AssertionError("the guest sent data on the ports connection")
    s.close()
    echo_guest(cid, listener, "blocking")
    echo_guest(cid, listener, "retry")
    echo_guest(cid, listener, "nonblocking")
    echo_guest(cid, listener, "nonblocking-retry")
    s, _ = accept_guest(cid, listener)
    check_data(read_to_eof(s), pattern(CLIENT_BULK))
    s.sendall(pattern(CLIENT_BULK))
    s.close()
    connections = [accept_guest(cid, listener) for _ in range(2)]
    for i, (s, peer_port) in enumerate(connections):
        message = read_to_eof(s)
        check_name(message, f"concurrent{i}", peer_port)
        s.sendall(message)
        s.close()


def main():
    global UDS
    if len(sys.argv) == 4 and sys.argv[1] == "--uds":
        UDS, console = sys.argv[2], sys.argv[3]
        cid = None
    elif len(sys.argv) == 3:
        cid, console = int(sys.argv[1]), sys.argv[2]
    else:
        print(__doc__, file=sys.stderr)
        return 2
    # The run's, as the run script passes it.
    timeout = int(os.environ.get("TIMEOUT", "120"))
    # Before the guest can connect.
    listener, refuser = host_sockets()
    wait_ready(console, time.monotonic() + timeout)
    try:
        concurrent(cid)
        refused(cid)
        churn(cid)
        after_close(cid)
        bulk(cid, BULK, slow=False)
        bulk(cid, SLOW, slow=True)
        local_shutdown(cid)
        nonblocking(cid)
        serve_guest(cid, listener, refuser)
    except (AssertionError, OSError) as error:
        print(f"FAIL: {error!r}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
