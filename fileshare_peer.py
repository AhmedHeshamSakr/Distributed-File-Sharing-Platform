
# fileshare_peer.py - with improvements
import socket
import threading
import os
import uuid
import time
import hashlib
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('FileSharePeer')

class FileSharePeer:
    def __init__(self, host, port, rendezvous_host, rendezvous_port):
        self.host, self.port = host, port
        self.rendezvous = (rendezvous_host, rendezvous_port)
        self.shared_files = {}  # {file_id: {name, path, size, hash}}
        self.shared_dir = Path("shared")
        self.shared_dir.mkdir(exist_ok=True)
        
        # Create server socket
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Keep track of active transfers
        self.active_transfers = {}
        self.lock = threading.Lock()
        self.running = True
    
    def start(self):
        """Start the peer server and register with rendezvous"""
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        
        # Register with rendezvous server
        self._register_with_rendezvous()
        
        # Start heartbeat thread
        threading.Thread(target=self._heartbeat_thread, daemon=True).start()
        
        # Load any previously shared files
        self._load_shared_files()
        
        logger.info(f"Peer running on {self.host}:{self.port}")
        
        try:
            while self.running:
                self.server.settimeout(1.0)  # Allow checking self.running
                try:
                    conn, addr = self.server.accept()
                    threading.Thread(target=self.handle_request, args=(conn, addr)).start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            logger.info("Peer shutting down...")
        finally:
            self.running = False
            self.server.close()
            self._save_shared_files()
    
    def _register_with_rendezvous(self):
        """Register this peer with the rendezvous server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(self.rendezvous)
            sock.send(f"REGISTER {self.host} {self.port}".encode())
            response = sock.recv(1024).decode()
            sock.close()
            
            if response.startswith("OK"):
                logger.info("Successfully registered with rendezvous server")
            else:
                logger.error(f"Failed to register: {response}")
        except Exception as e:
            logger.error(f"Failed to register with rendezvous server: {e}")
    
    def _heartbeat_thread(self):
        """Send periodic heartbeats to the rendezvous server"""
        while self.running:
            try:
                time.sleep(60)  # Send heartbeat every minute
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect(self.rendezvous)
                sock.send(b"HEARTBEAT")
                sock.recv(1024)
                sock.close()
                
                logger.debug("Sent heartbeat to rendezvous server")
            except Exception as e:
                logger.warning(f"Failed to send heartbeat: {e}")
    
    def _calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                sha256.update(block)
        return sha256.hexdigest()
    
    def _load_shared_files(self):
        """Load information about previously shared files"""
        metadata_path = self.shared_dir / "metadata.json"
        if metadata_path.exists():
            try:
                with open(metadata_path, 'r') as f:
                    self.shared_files = json.load(f)
                logger.info(f"Loaded {len(self.shared_files)} shared files from metadata")
            except Exception as e:
                logger.error(f"Failed to load shared files metadata: {e}")
    
    def _save_shared_files(self):
        """Save information about shared files"""
        metadata_path = self.shared_dir / "metadata.json"
        try:
            with open(metadata_path, 'w') as f:
                json.dump(self.shared_files, f)
            logger.info(f"Saved metadata for {len(self.shared_files)} files")
        except Exception as e:
            logger.error(f"Failed to save shared files metadata: {e}")
    
    def handle_request(self, conn, addr):
        """Handle incoming requests from other peers"""
        try:
            conn.settimeout(30)  # Set timeout for operations
            data = conn.recv(1024).decode()
            
            if data.startswith("UPLOAD"):
                self._handle_upload(conn, data)
            elif data == "SEARCH":
                self._handle_search(conn)
            elif data.startswith("DOWNLOAD"):
                self._handle_download(conn, data)
            elif data.startswith("INFO"):
                self._handle_file_info(conn, data)
            else:
                conn.send(b"ERROR: Invalid command")
                logger.warning(f"Invalid command from {addr}: {data}")
        except Exception as e:
            logger.error(f"Error handling request from {addr}: {e}")
        finally:
            conn.close()
    
    def _handle_upload(self, conn, data):
        """Handle file upload request"""
        try:
            # Parse header (UPLOAD filename filesize hash)
            parts = data.split(' ', 3)
            if len(parts) != 4:
                conn.send(b"ERROR: Invalid upload format")
                return
                
            _, name, size_str, file_hash = parts
            size = int(size_str)
            
            # Generate a unique ID for this file
            file_id = str(uuid.uuid4())
            path = self.shared_dir / file_id
            
            # Acknowledge upload request
            conn.send(f"OK: {file_id}".encode())
            
            # Read file data with progress tracking
            received = 0
            with open(path, 'wb') as f:
                while received < size:
                    remaining = size - received
                    chunk_size = min(4096, remaining)
                    chunk = conn.recv(chunk_size)
                    
                    if not chunk:
                        raise Exception("Connection closed before file was fully received")
                        
                    f.write(chunk)
                    received += len(chunk)
                    
                    # Send progress updates
                    if received % (1024*1024) == 0 or received == size:
                        progress = int(received * 100 / size)
                        conn.send(f"PROGRESS: {progress}".encode())
            
            # Verify file hash
            calculated_hash = self._calculate_file_hash(path)
            if calculated_hash != file_hash:
                os.remove(path)
                conn.send(b"ERROR: File hash verification failed")
                return
                
            # Store file metadata
            self.shared_files[file_id] = {
                "name": name,
                "path": str(path),
                "size": size,
                "hash": file_hash
            }
            
            # Save updated metadata
            self._save_shared_files()
            
            conn.send(b"SUCCESS: File uploaded successfully")
            logger.info(f"File uploaded: {name} ({size} bytes), ID: {file_id}")
            
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"Upload error: {e}")
    
    def _handle_search(self, conn):
        """Handle search request for available files"""
        try:
            # Format: file_id:name:size
            files = [f"{fid}:{info['name']}:{info['size']}" for fid, info in self.shared_files.items()]
            conn.send('\n'.join(files).encode())
            logger.debug(f"Sent information about {len(files)} files")
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"Search error: {e}")
    
    def _handle_file_info(self, conn, data):
        """Handle request for detailed information about a specific file"""
        try:
            _, file_id = data.split()
            
            if file_id in self.shared_files:
                info = self.shared_files[file_id]
                response = json.dumps({
                    "name": info["name"],
                    "size": info["size"],
                    "hash": info["hash"]
                })
                conn.send(response.encode())
            else:
                conn.send(b"ERROR: File not found")
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"File info error: {e}")
    
    def _handle_download(self, conn, data):
        """Handle file download request"""
        try:
            _, file_id = data.split()
            
            if file_id not in self.shared_files:
                conn.send(b"ERROR: File not found")
                return
                
            file_info = self.shared_files[file_id]
            file_path = file_info["path"]
            file_size = file_info["size"]
            
            # Send file header with metadata
            conn.send(f"FILE: {file_info['name']} {file_size} {file_info['hash']}".encode())
            
            # Wait for client acknowledgment
            response = conn.recv(1024).decode()
            if not response.startswith("OK"):
                logger.warning(f"Client rejected download: {response}")
                return
            
            # Send the file in chunks
            sent = 0
            with open(file_path, 'rb') as f:
                while sent < file_size:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                        
                    conn.sendall(chunk)
                    sent += len(chunk)
                    
                    # Get acknowledgment for larger files
                    if sent % (5*1024*1024) == 0:  # Every 5MB
                        conn.recv(1024)  # Wait for ACK
            
            logger.info(f"File {file_id} downloaded by {conn.getpeername()}")
            
        except Exception as e:
            try:
                conn.send(f"ERROR: {str(e)}".encode())
            except:
                pass  # Connection might be closed already
            logger.error(f"Download error: {e}")

    def share_file(self, filepath):
        """Share a local file (utility method for integration)"""
        try:
            if not os.path.exists(filepath):
                logger.error(f"File not found: {filepath}")
                return None
                
            # Calculate file hash and size
            file_hash = self._calculate_file_hash(filepath)
            file_size = os.path.getsize(filepath)
            file_name = os.path.basename(filepath)
            
            # Generate file ID and copy to shared directory
            file_id = str(uuid.uuid4())
            dest_path = self.shared_dir / file_id
            
            # Copy file
            with open(filepath, 'rb') as src, open(dest_path, 'wb') as dst:
                dst.write(src.read())
            
            # Store metadata
            self.shared_files[file_id] = {
                "name": file_name,
                "path": str(dest_path),
                "size": file_size,
                "hash": file_hash
            }
            
            # Save metadata
            self._save_shared_files()
            
            logger.info(f"Shared file: {file_name} ({file_size} bytes), ID: {file_id}")
            return file_id
            
        except Exception as e:
            logger.error(f"Error sharing file: {e}")
            return None
