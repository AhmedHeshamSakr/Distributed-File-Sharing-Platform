

# fileshare_client.py 
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
        self.session_id = None  
        self.username = None    

    def register(self, peer_ip, peer_port, username, password):
        """Register a new user with a peer"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((peer_ip, peer_port))
            sock.send(f"AUTH REGISTER {username} {password}".encode())
            
            response = sock.recv(1024).decode()
            sock.close()
            
            success = response.startswith("OK")
            message = response.split(':', 1)[1].strip() if ':' in response else response
            
            if success:
                logger.info(f"Successfully registered user: {username}")
            else:
                logger.error(f"Registration failed: {message}")
            
            return success, message
            
        except Exception as e:
            logger.error(f"Error during registration: {e}")
            return False, str(e)

    def login(self, peer_ip, peer_port, username, password):
        """Log in and get a session token"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((peer_ip, peer_port))
            sock.send(f"AUTH LOGIN {username} {password}".encode())
            
            response = sock.recv(1024).decode()
            sock.close()
            
            if response.startswith("OK"):
                parts = response.split(' ')
                if len(parts) >= 3:
                    self.session_id = parts[-1].strip()
                    self.username = username
                    logger.info(f"Successfully logged in as: {username}")
                    return True, "Login successful"
                else:
                    logger.error("Invalid login response format")
                    return False, "Invalid response from server"
            else:
                message = response.split(':', 1)[1].strip() if ':' in response else response
                logger.error(f"Login failed: {message}")
                return False, message
            
        except Exception as e:
            logger.error(f"Error during login: {e}")
            return False, str(e)

    def logout(self):
        """Clear the current session"""
        self.session_id = None
        self.username = None
        return True, "Logged out successfully"

    def is_authenticated(self):
        """Check if the client is currently authenticated"""
        return self.session_id is not None
        
    def authenticate_with_peer(self, peer_ip, peer_port):
        """Authenticate with a peer using existing session info"""
        if not self.is_authenticated() or not self.username:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((peer_ip, peer_port))
            sock.send(f"AUTH SESSION {self.username} {self.session_id}".encode())
            response = sock.recv(1024).decode()
            sock.close()
            return response.startswith("OK")
        except Exception as e:
            logger.error(f"Error authenticating with peer: {e}")
            return False

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
                            parts = file_line.split(':')
                            if len(parts) >= 3:  # At least need id:name:size
                                try:
                                    file_id = parts[0]
                                    file_name = parts[1]
                                    file_size = int(parts[2])
                                    owner = parts[3] if len(parts) > 3 else "unknown"
                                    all_files.append((ip, port, file_id, file_name, file_size))
                                except (ValueError, IndexError) as e:
                                    logger.warning(f"Invalid file info format from {ip}:{port}: {file_line} - {e}")
                                    continue
                
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
        
        # Check authentication
        if not self.is_authenticated():
            logger.error("Authentication required to upload files")
            return False
            
        try:
            # Calculate file size
            file_size = os.path.getsize(filepath)
            file_name = os.path.basename(filepath)
            
            # Connect to peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # Longer timeout for large files
            sock.connect((peer_ip, peer_port))
            
            # Send upload request with metadata and session
            sock.send(f"UPLOAD {file_name} {file_size} {self.session_id}".encode())
            
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
        sock = None
        temp_path = None
        
        # Check authentication
        if not self.is_authenticated():
            logger.error("Authentication required to download files")
            return False
        
        try:
            # Connect to peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((peer_ip, peer_port))
            
            # Send download request with session ID
            sock.send(f"DOWNLOAD {file_id} {self.session_id}".encode())
            
            # Get file metadata
            sock.settimeout(10)
            response = sock.recv(1024).decode()
            
            if response.startswith("ERROR"):
                logger.error(f"Download error: {response}")
                return False
                    
            try:
                # Parse JSON metadata
                metadata = json.loads(response)
                file_name = metadata["filename"]
                file_size = int(metadata["size"])
                
                if file_size <= 0:
                    logger.error(f"Invalid file size: {file_size}")
                    return False
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                logger.error(f"Error parsing metadata: {e}")
                return False
            
            # Determine save path
            if save_path is None:
                save_path = self.download_dir / file_name
            
            # Use temporary file
            temp_path = f"{save_path}.part"
            
            # Acknowledge
            sock.send(b"OK: Ready to receive")
            
            # Receive file
            received = 0
            start_time = time.time()
            
            with open(temp_path, 'wb') as f:
                sock.settimeout(30)
                
                while received < file_size:
                    try:
                        remaining = file_size - received
                        chunk_size = min(4096, remaining)
                        chunk = sock.recv(chunk_size)
                        
                        if not chunk:
                            break
                            
                        f.write(chunk)
                        received += len(chunk)
                        
                        # Progress reporting
                        now = time.time()
                        if now - start_time >= 1 or received == file_size:
                            progress = min(100, int(received * 100 / file_size))
                            speed = received / (now - start_time) / 1024
                            logger.info(f"Progress: {progress}% ({speed:.1f} KB/s)")
                            start_time = now
                            
                    except socket.timeout:
                        continue
                    except socket.error as e:
                        logger.error(f"Socket error: {e}")
                        return False
            
            # Verify completion
            if received < file_size:
                logger.error(f"Incomplete download: {received}/{file_size} bytes")
                return False
                
            # Finalize download
            os.replace(temp_path, save_path)
            logger.info(f"Download complete: {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False
            
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
                    
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass

        
    def _safe_socket_operation(self, sock, operation, *args, timeout=10, retries=3):
        """Perform a socket operation safely with timeouts and retries"""
        original_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        
        for attempt in range(retries):
            try:
                if operation == "send":
                    return sock.send(*args)
                elif operation == "recv":
                    return sock.recv(*args)
                elif operation == "sendall":
                    return sock.sendall(*args)
                elif operation == "connect":
                    return sock.connect(*args)
                else:
                    raise ValueError(f"Unknown socket operation: {operation}")
            except socket.timeout:
                if attempt < retries - 1:
                    logger.debug(f"Socket {operation} timed out, retrying ({attempt+1}/{retries})")
                    continue
                else:
                    raise
            except socket.error as e:
                logger.error(f"Socket error during {operation}: {e}")
                raise
            finally:
                # Restore original timeout
                try:
                    sock.settimeout(original_timeout)
                except:
                    pass
    
