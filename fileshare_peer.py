import socket
import threading
import os
import uuid

class FileSharePeer:
    def __init__(self, host, port, rendezvous_host, rendezvous_port):
        self.host, self.port = host, port
        self.rendezvous = (rendezvous_host, rendezvous_port)
        self.shared_files = {}  # {file_id: {name, path}}
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    def start(self):
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        self._register_with_rendezvous()
        print(f"Peer running on {self.host}:{self.port}")
        while True:
            conn, addr = self.server.accept()
            threading.Thread(target=self.handle_request, args=(conn,)).start()
    
    def _register_with_rendezvous(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(self.rendezvous)
            sock.send(f"REGISTER {self.host} {self.port}".encode())
            sock.recv(1024)
            sock.close()
        except Exception as e:
            print(f"Failed to register: {e}")
    
    def handle_request(self, conn):
        try:
            data = conn.recv(1024).decode()
            if data.startswith("UPLOAD"):
                _, name = data.split(' ', 1)
                file_id = str(uuid.uuid4())
                path = os.path.join("shared", file_id)
                with open(path, 'wb') as f:
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk: break
                        f.write(chunk)
                self.shared_files[file_id] = {"name": name, "path": path}
                conn.send(b"Uploaded")
            elif data == "SEARCH":
                files = [f"{fid}:{info['name']}" for fid, info in self.shared_files.items()]
                conn.send('\n'.join(files).encode())
            elif data.startswith("DOWNLOAD"):
                _, fid = data.split()
                if fid in self.shared_files:
                    with open(self.shared_files[fid]["path"], 'rb') as f:
                        conn.send(f.read())
                else:
                    conn.send(b"File not found")
            else:
                conn.send(b"Invalid command")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            conn.close()