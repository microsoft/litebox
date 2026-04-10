import socket, sys, os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 22))
s.listen(1)
sys.stderr.write("TCP echo (forking) listening on port 22\n")
sys.stderr.flush()

conn, addr = s.accept()
sys.stderr.write(f"Connection from {addr}, forking...\n")
sys.stderr.flush()

pid = os.fork()
if pid > 0:
    # Parent: close accepted socket, keep listening
    conn.close()
    sys.stderr.write(f"Parent: forked child {pid}, waiting\n")
    sys.stderr.flush()
    os.waitpid(pid, 0)
    sys.stderr.write("Parent: child exited\n")
    sys.stderr.flush()
    s.close()
else:
    # Child: close listen socket, handle connection
    s.close()
    sys.stderr.write(f"Child: handling connection from {addr}\n")
    sys.stderr.flush()
    while True:
        data = conn.recv(4096)
        if not data:
            break
        sys.stderr.write(f"Child: received {len(data)} bytes: {data[:50]}\n")
        sys.stderr.flush()
        conn.sendall(data)
    conn.close()
    sys.stderr.write("Child: done\n")
    sys.stderr.flush()
    os._exit(0)
