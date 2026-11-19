#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Host end of vsock.c: usage `vsock.host.py PATH OUTPUT`.

Hybrid vsock, over Unix sockets only: the guest's port P is reached by
connecting to PATH and sending `CONNECT P\\n` (reply `OK <port>\\n`, or a
close if refused), and the host's port P is the Unix socket PATH_P. The
bridge may or may not pass half-closes on (Cloud Hypervisor's does from v53),
so a message's length tells where it ends, and either side's close ends a
connection. Once the guest prints `ready` to the run's output file OUTPUT,
connects to its listeners for vsock.c's scenarios, in order, and once to a
port nothing listens on, which must be refused; then sends the guest two host
ports, one listening and one refusing, and serves its connections. Exits 0 if
all went as expected.
"""

import os
import socket
import sys
import time

# As vsock.json's port, and vsock.c's offsets from it.
PORT = 3000
UNUSED_PORT = PORT + 2
NONBLOCKING_PORT = PORT + 3
HOST_PORTS_PORT = PORT + 4
HOST_ECHO_PORT = 3100
HOST_REFUSING_PORT = 3101
# As vsock.c's.
NAME_LEN = 64
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
# Each receive's size, and the pause before it, of slow readers.
SLOW_BUFFER = 4096
SLOW_PAUSE = 0.001
# Each step's; the run script's TIMEOUT bounds the whole.
STEP_TIMEOUT = 60

PATH = None


def pattern(length):
    return bytes((i * 7 + i // 4096) & 0xFF for i in range(length))


def name(text):
    """`text`, NUL-padded to NAME_LEN bytes."""
    return text.encode().ljust(NAME_LEN, b"\0")


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


def connect(port):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(STEP_TIMEOUT)
    s.connect(PATH)
    s.sendall(f"CONNECT {port}\n".encode())
    # One byte at a time: what follows the line is the guest's.
    reply = b""
    while not reply.endswith(b"\n"):
        byte = s.recv(1)
        if not byte:
            s.close()
            raise ConnectionRefusedError(f"port {port} refused the connection")
        reply += byte
    if not reply.startswith(b"OK ") or not reply[3:-1].isdigit():
        s.close()
        raise AssertionError(f"reply {reply!r} to CONNECT {port}")
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


def check_eof(s):
    data = s.recv(1)
    if data:
        raise AssertionError(f"{data!r} instead of EOF")


def concurrent():
    sockets = [connect(PORT) for _ in range(2)]
    messages = [name(f"hello from connection {i}") for i in range(2)]
    # Both open before either sends.
    for s, message in reversed(list(zip(sockets, messages))):
        s.sendall(message)
    for s, message in zip(sockets, messages):
        check_data(read_exactly(s, NAME_LEN), message)
        check_eof(s)
        s.close()


def refused():
    try:
        connect(UNUSED_PORT).close()
    except (ConnectionRefusedError, ConnectionResetError):
        return
    raise AssertionError(f"connected to port {UNUSED_PORT}, where nothing listens")


def churn():
    for i in range(CHURN):
        s = connect(PORT)
        kind = i % 3
        if kind == 0:
            expected = name(f"ping {i}")
            s.sendall(expected)
        elif kind == 1:
            expected = name(f"hello {i}")
        else:
            s.sendall(name(f"abort {i}"))
            s.close()
            continue
        check_data(read_exactly(s, NAME_LEN), expected)
        check_eof(s)
        s.close()


def send_until_closed(s):
    deadline = time.monotonic() + STEP_TIMEOUT
    while time.monotonic() < deadline:
        try:
            s.send(b"more")
        except (BrokenPipeError, ConnectionResetError):
            return
        time.sleep(0.01)
    raise AssertionError("sends after the guest closed did not fail")


def after_close():
    for _ in range(AFTER_CLOSE):
        s = connect(PORT)
        s.sendall(REQUEST)
        # The guest replies and closes meanwhile, while this end does not
        # read: the reply fits in this end's buffer.
        time.sleep(0.2)
        send_until_closed(s)
        check_data(read_to_eof(s, slow=True), pattern(REPLY))
        s.close()


def bulk(size, slow):
    s = connect(PORT)
    data = pattern(size)
    s.sendall(data)
    check_data(read_exactly(s, size, slow), data)
    # The guest waits for this, and the close, before it ends.
    s.sendall(ACK)
    s.close()


def local_shutdown():
    s = connect(PORT)
    s.sendall(QUEUED)
    check_data(read_exactly(s, len(REPLIED)), REPLIED)
    check_eof(s)
    s.close()


def nonblocking():
    s = connect(NONBLOCKING_PORT)
    s.sendall(pattern(FIRST))
    # The guest finds no more data before this.
    check_data(read_exactly(s, len(GO)), GO)
    s.sendall(LATER)
    check_data(read_exactly(s, BACKPRESSURE, slow=True), pattern(BACKPRESSURE))
    s.sendall(ACK)
    s.close()
    s = connect(NONBLOCKING_PORT)
    s.sendall(ACCEPT4)
    check_data(read_exactly(s, len(ACCEPT4)), ACCEPT4)
    check_eof(s)
    s.close()


def host_sockets():
    """PATH_HOST_ECHO_PORT, listening, and PATH_HOST_REFUSING_PORT, bound
    without listening, which refuses connections."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.settimeout(STEP_TIMEOUT)
    listener.bind(f"{PATH}_{HOST_ECHO_PORT}")
    listener.listen(8)
    refuser = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    refuser.bind(f"{PATH}_{HOST_REFUSING_PORT}")
    return listener, refuser


def accept_guest(listener):
    s, _ = listener.accept()
    s.settimeout(STEP_TIMEOUT)
    return s


def check_name(received, prefix):
    """Checks the guest's `NAME PORT`, NUL-padded."""
    text = received.rstrip(b"\0").decode(errors="replace")
    words = text.split(" ")
    if len(words) != 2 or words[0] != prefix or not words[1].isdigit():
        raise AssertionError(f"name {received!r}, expected `{prefix} PORT`")


def echo_guest(listener, prefix):
    s = accept_guest(listener)
    message = read_exactly(s, NAME_LEN)
    check_name(message, prefix)
    s.sendall(message)
    s.close()


def serve_guest(listener):
    s = connect(HOST_PORTS_PORT)
    s.sendall(f"{HOST_ECHO_PORT} {HOST_REFUSING_PORT}".encode())
    s.close()
    echo_guest(listener, "blocking")
    echo_guest(listener, "retry")
    echo_guest(listener, "nonblocking")
    echo_guest(listener, "nonblocking-retry")
    s = accept_guest(listener)
    check_data(read_exactly(s, CLIENT_BULK), pattern(CLIENT_BULK))
    s.sendall(pattern(CLIENT_BULK))
    s.close()
    connections = [accept_guest(listener) for _ in range(2)]
    for i, s in enumerate(connections):
        message = read_exactly(s, NAME_LEN)
        check_name(message, f"concurrent{i}")
        s.sendall(message)
        s.close()


def main():
    global PATH
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    PATH, console = sys.argv[1], sys.argv[2]
    timeout = int(os.environ.get("TIMEOUT", "120"))
    # Before the guest can connect.
    listener, refuser = host_sockets()
    try:
        wait_ready(console, time.monotonic() + timeout)
        concurrent()
        refused()
        churn()
        after_close()
        bulk(BULK, slow=False)
        bulk(SLOW, slow=True)
        local_shutdown()
        nonblocking()
        serve_guest(listener)
    except (AssertionError, OSError) as error:
        print(f"FAIL: {error!r}")
        return 1
    finally:
        for s, port in ((listener, HOST_ECHO_PORT), (refuser, HOST_REFUSING_PORT)):
            s.close()
            os.unlink(f"{PATH}_{port}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
