#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Host end of vsock_hybrid.c: usage `vsock_hybrid.host.py PATH CONSOLE`.

Hybrid vsock, over Unix sockets only: the guest's port P is reached by
connecting to PATH and sending `CONNECT P\\n` (reply `OK <port>\\n`, or a
close if refused), and the host's port P is the Unix socket PATH_P. Once the
guest prints `ready` to the console file CONSOLE, runs vsock_hybrid.c's
scenarios in order, then serves the guest's connects. No half-close. Exits 0
if all went as expected.
"""

import os
import socket
import sys
import time

# As vsock_hybrid.c's.
PORT = 1024
SIGNAL_PORT = 1025
UNUSED_PORT = 1026
HOST_ECHO_PORT = 2000
HOST_REFUSING_PORT = 2001
MESSAGE = 64
CONCURRENT = 4
BULK = 1024 * 1024
SHUT = b"shut"
# The receive buffer, and the pause between receives, of the slow reader.
SLOW_BUFFER = 4096
SLOW_PAUSE = 0.001
# Each blocking socket call's; the caller's TIMEOUT bounds the whole.
STEP_TIMEOUT = 60

PATH = None


def pattern(length, offset=0):
    return bytes(((i * 7 + i // 4096) & 0xFF) for i in range(offset, offset + length))


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


def check_open(s):
    """No data and no EOF yet."""
    s.setblocking(False)
    try:
        data = s.recv(1)
    except BlockingIOError:
        return
    finally:
        s.settimeout(STEP_TIMEOUT)
    raise AssertionError(f"{data!r} where nothing was sent" if data else "EOF before the close")


def echo():
    s = connect(PORT)
    s.sendall(pattern(MESSAGE))
    check_data(read_exactly(s, MESSAGE), pattern(MESSAGE))
    s.close()


def refused():
    try:
        connect(UNUSED_PORT).close()
    except (ConnectionRefusedError, ConnectionResetError):
        return
    raise AssertionError(f"connected to port {UNUSED_PORT}, where nothing listens")


def concurrent():
    sockets = [connect(PORT) for _ in range(CONCURRENT)]
    # All open before any sends.
    for i, s in reversed(list(enumerate(sockets))):
        s.sendall(pattern(MESSAGE, i * MESSAGE))
    for i, s in enumerate(sockets):
        check_data(read_exactly(s, MESSAGE), pattern(MESSAGE, i * MESSAGE))
        s.close()


def bulk():
    s = connect(PORT)
    s.sendall(pattern(BULK))
    check_data(read_exactly(s, BULK, slow=True), pattern(BULK))
    s.close()


def host_close():
    s = connect(PORT)
    s.sendall(pattern(MESSAGE))
    s.close()


def guest_close():
    s = connect(PORT)
    # The guest never reads this.
    s.sendall(pattern(MESSAGE, MESSAGE))
    check_data(read_exactly(s, MESSAGE), pattern(MESSAGE))
    check_eof(s)
    s.close()


def guest_shutdown():
    s = connect(PORT)
    signal = connect(SIGNAL_PORT)
    check_data(read_exactly(s, MESSAGE), pattern(MESSAGE))
    # The guest shut down sending before it sent this.
    check_data(read_exactly(signal, len(SHUT)), SHUT)
    check_open(s)
    s.sendall(pattern(MESSAGE, MESSAGE))
    check_eof(s)
    s.close()
    signal.close()


def host_sockets():
    """PATH_P listening for HOST_ECHO_PORT; PATH_Q bound, not listening, for
    HOST_REFUSING_PORT."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.settimeout(STEP_TIMEOUT)
    listener.bind(f"{PATH}_{HOST_ECHO_PORT}")
    listener.listen(1)
    refuser = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    refuser.bind(f"{PATH}_{HOST_REFUSING_PORT}")
    return listener, refuser


def serve_guest(listener):
    s, _ = listener.accept()
    s.settimeout(STEP_TIMEOUT)
    message = read_exactly(s, MESSAGE)
    check_data(message, pattern(MESSAGE, 2 * MESSAGE))
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
        echo()
        refused()
        concurrent()
        bulk()
        host_close()
        guest_close()
        guest_shutdown()
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
