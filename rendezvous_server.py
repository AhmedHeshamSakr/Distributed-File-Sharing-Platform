import socket
import threading

class RendezvousServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host, self.port = host, port
        self.peers = []
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    def start(self):
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Rendezvous Server running on {self.host}:{self.port}")
        while True:
            conn, addr = self.server.accept()
            threading.Thread(target=self.handle_client, args=(conn,)).start()
    
    def handle_client(self, conn):
        try:
            data = conn.recv(1024).decode()
            if data.startswith("REGISTER"):
                _, ip, port = data.split()
                self.peers.append((ip, int(port)))
                conn.send(b"OK")
            elif data == "GET_PEERS":
                conn.send(str(self.peers).encode())
            else:
                conn.send(b"Invalid command")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    server = RendezvousServer()
    server.start()