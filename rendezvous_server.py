# Directory structure:
# p2p_file_share/
# ├── rendezvous_server.py
# ├── fileshare_peer.py
# ├── fileshare_client.py
# ├── run_server.py
# └── run_peer.py

# rendezvous_server.py - with improvements
import socket
import threading
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('RendezvousServer')

class RendezvousServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host, self.port = host, port
        self.peers = []  # List of active peers (ip, port)
        self.peer_last_seen = {}  # Track peer activity
        self.lock = threading.Lock()  # For thread safety
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    def start(self):
        """Start the rendezvous server and begin accepting connections"""
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        logger.info(f"Rendezvous Server running on {self.host}:{self.port}")
        
        # Start a thread to clean inactive peers
        threading.Thread(target=self._clean_inactive_peers, daemon=True).start()
        
        try:
            while True:
                conn, addr = self.server.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
        finally:
            self.server.close()
    
    def _clean_inactive_peers(self):
        """Remove peers that haven't been seen in the last 5 minutes"""
        while True:
            time.sleep(60)  # Check every minute
            now = time.time()
            inactive_peers = []
            
            with self.lock:
                for (ip, port), last_seen in list(self.peer_last_seen.items()):
                    if now - last_seen > 300:  # 5 minutes
                        inactive_peers.append((ip, port))
                        
                for peer in inactive_peers:
                    if peer in self.peers:
                        self.peers.remove(peer)
                    if peer in self.peer_last_seen:
                        del self.peer_last_seen[peer]
                        
            if inactive_peers:
                logger.info(f"Removed {len(inactive_peers)} inactive peers")
    
    def handle_client(self, conn, addr):
        """Handle incoming client connections"""
        try:
            conn.settimeout(10)  # Set timeout for receiving data
            data = conn.recv(1024).decode()
            
            if data.startswith("REGISTER"):
                self._handle_register(conn, data)
            elif data == "GET_PEERS":
                self._handle_get_peers(conn)
            elif data == "HEARTBEAT":
                self._handle_heartbeat(conn, addr)
            else:
                conn.send(b"ERROR: Invalid command")
                logger.warning(f"Invalid command from {addr}: {data}")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            conn.close()
    
    def _handle_register(self, conn, data):
        """Register a new peer in the network"""
        try:
            _, ip, port = data.split()
            port = int(port)
            peer = (ip, port)
            
            with self.lock:
                if peer not in self.peers:
                    self.peers.append(peer)
                self.peer_last_seen[peer] = time.time()
            
            conn.send(b"OK: Registered successfully")
            logger.info(f"Registered new peer: {ip}:{port}")
        except ValueError:
            conn.send(b"ERROR: Invalid register format")
            logger.warning(f"Invalid register format: {data}")
    
    def _handle_get_peers(self, conn):
        """Send the list of peers to the client"""
        with self.lock:
            # Convert peers to a safer string format
            peer_list = ";".join([f"{ip}:{port}" for ip, port in self.peers])
        
        conn.send(peer_list.encode())
        logger.debug(f"Sent peer list ({len(self.peers)} peers)")
    
    def _handle_heartbeat(self, conn, addr):
        """Update the last seen time for a peer"""
        peer_ip = addr[0]
        
        with self.lock:
            for peer in self.peers:
                if peer[0] == peer_ip:
                    self.peer_last_seen[peer] = time.time()
                    break
        
        conn.send(b"OK")

