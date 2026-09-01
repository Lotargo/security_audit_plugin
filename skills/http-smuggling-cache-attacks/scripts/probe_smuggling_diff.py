#!/usr/bin/env python3
import socket
import ssl
import sys
import time

def probe_cl_te(host, port=443):
    payload = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"0\r\n\r\n"
    ).encode('utf-8')

    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            start = time.time()
            ssock.sendall(payload)
            try:
                resp = ssock.recv(1024)
                duration = time.time() - start
                return {"host": host, "response_time_sec": duration, "status_snippet": resp[:50].decode('latin1', errors='ignore')}
            except socket.timeout:
                return {"host": host, "timeout": True, "note": "Potential backend timeout desynchronization"}

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    import json
    print(json.dumps(probe_cl_te(target), indent=2))
