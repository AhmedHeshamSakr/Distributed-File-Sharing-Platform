

# fileshare_client.py - with improvements
import socket
import os
import time
import hashlib
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('FileShareClient')

class FileShareClient:
    def __init__(self, rendezvous_host, rendezvous_port):
        self.rendezvous = (rendezvous_host, rendezvous_port)
        self.download_dir = Path("downloads")
        self.download_dir.mkdir(exist_ok=True)
    
    def get_peers(self):
        """Get list of active peers from rendezvous server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(self.rendezvous)
            sock.send(b"GET_PEERS")
            
            response = sock.recv(4096).decode()
            sock.close()
            
            if not response or response.startswith("ERROR"):
                logger.error(f"Failed to get peers: {response}")
                return []
            
            # Parse response format "ip:port;ip:port;..."
            peers = []
            for peer_str in response.split(';'):
                if peer_str:
                    ip, port = peer_str.split(':')
                    peers.append((ip, int(port)))
            
            logger.info(f"Found {len(peers)} active peers")
            return peers
            
        except Exception as e:
            logger.error(f"Error getting peers: {e}")
            return []
    
    def search_files(self):
        """Search for available files across all peers"""
        peers = self.get_peers()
        all_files = []  # List of (peer_ip, peer_port, file_id, file_name, file_size)
        
        for ip, port in peers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                sock.send(b"SEARCH")
                
                response = sock.recv(4096).decode()
                sock.close()
                
                if response and not response.startswith("ERROR"):
                    for file_line in response.split('\n'):
                        if file_line:
                            parts = file_line.split(':', 2)
                            if len(parts) == 3:
                                file_id, file_name, file_size = parts
                                all_files.append((ip, port, file_id, file_name, int(file_size)))
                
            except Exception as e:
                logger.warning(f"Error searching peer {ip}:{port}: {e}")
        
        logger.info(f"Found {len(all_files)} files across {len(peers)} peers")
        return all_files
    
    def get_file_info(self, peer_ip, peer_port, file_id):
        """Get detailed information about a specific file"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((peer_ip, peer_port))
            sock.send(f"INFO {file_id}".encode())
            
            response = sock.recv(1024).decode()
            sock.close()
            
            if response.startswith("ERROR"):
                logger.error(f"Failed to get file info: {response}")
                return None
                
            return json.loads(response)
            
        except Exception as e:
            logger.error(f"Error getting file info: {e}")
            return None
    
    def upload_file(self, filepath, peer_ip, peer_port):
        """Upload a file to a specific peer"""
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return False
            
        try:
            # Calculate file hash and size
            file_hash = self._calculate_file_hash(filepath)
            file_size = os.path.getsize(filepath)
            file_name = os.path.basename(filepath)
            
            # Connect to peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # Longer timeout for large files
            sock.connect((peer_ip, peer_port))
            
            # Send upload request with metadata
            sock.send(f"UPLOAD {file_name} {file_size} {file_hash}".encode())
            
            # Get acknowledgment and file ID
            response = sock.recv(1024).decode()
            if not response.startswith("OK"):
                logger.error(f"Peer rejected upload: {response}")
                sock.close()
                return False
                
            file_id = response.split(':', 1)[1].strip()
            
            # Send file data
            sent = 0
            start_time = time.time()
            last_progress = 0
            
            with open(filepath, 'rb') as f:
                while sent < file_size:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                        
                    sock.sendall(chunk)
                    sent += len(chunk)
                    
                    # Get progress updates
                    if sent == file_size or sent - last_progress >= 1024*1024:  # Every 1MB
                        progress_msg = sock.recv(1024).decode()
                        if progress_msg.startswith("PROGRESS"):
                            progress = int(progress_msg.split(':')[1].strip())
                            elapsed = time.time() - start_time
                            speed = sent / elapsed / 1024 if elapsed > 0 else 0
                            logger.info(f"Upload progress: {progress}% ({speed:.1f} KB/s)")
                            last_progress = sent
            
            # Get final status
            final_status = sock.recv(1024).decode()
            sock.close()
            
            if final_status.startswith("SUCCESS"):
                logger.info(f"Upload successful: {file_name} -> {peer_ip}:{peer_port}")
                return True
            else:
                logger.error(f"Upload failed: {final_status}")
                return False
                
        except Exception as e:
            logger.error(f"Error uploading file: {e}")
            return False
    
    def download_file(self, peer_ip, peer_port, file_id, save_path=None):
        """Download a file from a specific peer"""
        try:
            # Connect to peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # Longer timeout for large files
            sock.connect((peer_ip, peer_port))
            
            # Send download request
            sock.send(f"DOWNLOAD {file_id}".encode())
            
            # Get file metadata
            response = sock.recv(1024).decode()
            if response.startswith("ERROR"):
                logger.error(f"Download error: {response}")
                sock.close()
                return False
                
            if not response.startswith("FILE:"):
                logger.error(f"Invalid response: {response}")
                sock.close()
                return False
            
            # Parse file metadata
            # Format: "FILE: filename size hash"
            _, metadata = response.split(':', 1)
            parts = metadata.strip().split(' ', 2)
            if len(parts) != 3:
                logger.error(f"Invalid file metadata: {metadata}")
                sock.close()
                return False
                
            file_name, file_size_str, file_hash = parts
            file_size = int(file_size_str)
            
            # Determine save path
            if save_path is None:
                save_path = self.download_dir / file_name
            
            # Acknowledge and start download
            sock.send(b"OK: Ready to receive")
            
            # Receive file
            received = 0
            start_time = time.time()
            last_progress_report = 0
            
            with open(save_path, 'wb') as f:
                while received < file_size:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                        
                    f.write(chunk)
                    received += len(chunk)
                    
                    # Send acknowledgment for large files
                    if received % (5*1024*1024) == 0:  # Every 5MB
                        sock.send(b"ACK")
                    
                    # Print progress
                    now = time.time()
                    if now - last_progress_report >= 1 or received == file_size:
                        progress = int(received * 100 / file_size)
                        speed = received / (now - start_time) / 1024 if now > start_time else 0
                        logger.info(f"Download progress: {progress}% ({speed:.1f} KB/s)")
                        last_progress_report = now
            
            sock.close()
            
            # Verify file hash
            if received != file_size:
                logger.error(f"Incomplete download: got {received}/{file_size} bytes")
                return False
                
            calculated_hash = self._calculate_file_hash(save_path)
            if calculated_hash != file_hash:
                logger.error("File hash verification failed")
                return False
                
            logger.info(f"Download successful: {file_name} saved to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Download error: {e}")
            return False
    
    def _calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                sha256.update(block)
        return sha256.hexdigest()

