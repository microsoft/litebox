#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Host client of the vsock test: usage `vsock.host.py CID CONSOLE`.

Waits for the guest's `ready` line in the console output file CONSOLE, then
connects to guest CID, port 1024, for the scenarios vsock.c serves, in its
order, with a refused connection to a port nothing listens on after the
first; exits 0 if all of them went as expected.
"""

import os
import socket
import sys
import time

PORT = 1024
UNUSED_PORT = 1025
# As vsock.c's.
BULK = 2 * 1024 * 1024
SLOW = 256 * 1024
CHURN = 40
AFTER_CLOSE = 3
REQUEST = b"request!"
REPLY = 64 * 1024
ACK = b"ack"
# The receive buffer, and the pause between receives, of slow readers.
SLOW_BUFFER = 4096
SLOW_PAUSE = 0.001
# Each step's; the run script's TIMEOUT bounds the whole.
STEP_TIMEOUT = 60


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


def connect(cid, port, slow=False):
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
        s = connect(cid, PORT, slow=True)
        s.sendall(REQUEST)
        # The guest replies and closes meanwhile; little of the reply fits
        # in this end's buffer, so the rest waits in the closing guest.
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


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    cid, console = int(sys.argv[1]), sys.argv[2]
    # The run's, as the run script passes it.
    timeout = int(os.environ.get("TIMEOUT", "120"))
    wait_ready(console, time.monotonic() + timeout)
    try:
        concurrent(cid)
        refused(cid)
        churn(cid)
        after_close(cid)
        bulk(cid, BULK, slow=False)
        bulk(cid, SLOW, slow=True)
    except (AssertionError, OSError) as error:
        print(f"FAIL: {error!r}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
