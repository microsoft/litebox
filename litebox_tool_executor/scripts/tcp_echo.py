import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 22))
s.listen(1)
sys.stderr.write("TCP echo listening on port 22\n")
sys.stderr.flush()
conn, addr = s.accept()
sys.stderr.write(f"Connection from {addr}\n")
sys.stderr.flush()
while True:
    data = conn.recv(4096)
    if not data:
        break
    sys.stderr.write(f"Received {len(data)} bytes: {data[:50]}\n")
    sys.stderr.flush()
    conn.sendall(data)
conn.close()
s.close()
