import socket
import os

class Client:
    def __init__(self, rendezvous_host, rendezvous_port):
        self.rendezvous = (rendezvous_host, rendezvous_port)
    
    def _get_peers(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.rendezvous)
        sock.send(b"GET_PEERS")
        peers = eval(sock.recv(1024).decode())  # List of (ip, port)
        sock.close()
        return peers
    
    def share(self, filepath, peer_ip, peer_port):
        try:
            with open(filepath, 'rb') as f:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((peer_ip, peer_port))
                sock.send(f"UPLOAD {os.path.basename(filepath)}".encode())
                sock.send(f.read())
                print(sock.recv(1024).decode())
                sock.close()
        except Exception as e:
            print(f"Error: {e}")
    
    def search(self):
        peers = self._get_peers()
        files = []
        for ip, port in peers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((ip, port))
                sock.send(b"SEARCH")
                response = sock.recv(4096).decode().split('\n')
                files.extend([(ip, port, f.split(':', 1)) for f in response if f])
                sock.close()
            except:
                continue
        return files
    
    def download(self, peer_ip, peer_port, file_id, save_path):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))
            sock.send(f"DOWNLOAD {file_id}".encode())
            data = sock.recv(4096)
            if data == b"File not found":
                print("File not found")
            else:
                with open(save_path, 'wb') as f:
                    f.write(data)
                print("Downloaded")
            sock.close()
        except Exception as e:
            print(f"Error: {e}")