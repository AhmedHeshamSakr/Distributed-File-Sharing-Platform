

# fileshare_client.py 
import socket
import os
import time
import hashlib
import json
import logging
import crypto_utils
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
            logger.warning("Not authenticated locally, can't authenticate with peer")
            return False
            
        try:
            logger.debug(f"Authenticating with peer {peer_ip}:{peer_port} as {self.username}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((peer_ip, peer_port))
            
            # First try direct session authentication
            auth_command = f"AUTH SESSION {self.username} {self.session_id}"
            sock.send(auth_command.encode())
            
            response = sock.recv(1024).decode()
            
            if response.startswith("OK"):
                logger.debug(f"Successfully authenticated with peer {peer_ip}:{peer_port}")
                sock.close()
                return True
                
            # If direct authentication fails, try sync validation
            sync_command = f"SYNC VALIDATE_SESSION {self.username}:{self.session_id}"
            sock.send(sync_command.encode())
            
            response = sock.recv(1024).decode()
            sock.close()
            
            if response.startswith("OK"):
                logger.info(f"Successfully validated session with peer {peer_ip}:{peer_port}")
                return True
            else:
                logger.warning(f"Session validation failed with peer {peer_ip}:{peer_port}: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Error authenticating with peer {peer_ip}:{peer_port}: {e}")
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
    
    def download_file(self, peer_ip, peer_port, file_id, save_path=None):
        """Download a file from a specific peer with proper authentication and integrity verification"""
        sock = None
        temp_path = None
        
        # Check local authentication
        if not self.is_authenticated():
            logger.error("Not authenticated locally. Please log in first.")
            return False
        
        try:
            # First, authenticate with the target peer
            if not self.authenticate_with_peer(peer_ip, peer_port):
                logger.warning(f"Not authenticated with peer {peer_ip}:{peer_port}. Attempting direct login...")
                
                # Try to authenticate using existing credentials
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((peer_ip, peer_port))
                
                # Use the session token as a form of credential (this relies on session sync between peers)
                auth_command = f"AUTH SESSION {self.username} {self.session_id}"
                sock.send(auth_command.encode())
                
                response = sock.recv(1024).decode()
                sock.close()
                
                if not response.startswith("OK"):
                    logger.error(f"Failed to authenticate with peer {peer_ip}:{peer_port}")
                    return False
                
                logger.info(f"Successfully authenticated with peer {peer_ip}:{peer_port}")
            
            # Now proceed with the download process
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # Longer timeout for file transfer
            sock.connect((peer_ip, peer_port))
            
            # Send download request with session ID
            download_command = f"DOWNLOAD {file_id} {self.session_id}"
            sock.send(download_command.encode())
            
            # Get file metadata
            sock.settimeout(10)
            response = sock.recv(4096).decode()  # Using larger buffer for potential JSON metadata
            
            if response.startswith("ERROR"):
                logger.error(f"Download error: {response}")
                return False
            
            try:
                # Parse JSON metadata
                metadata = json.loads(response)
                file_name = metadata["filename"]
                file_size = int(metadata["size"])
                
                # Get hash for integrity verification if available
                file_hash = None
                if "hash" in metadata and metadata["hash"]:
                    file_hash = crypto_utils.decode_bytes(metadata["hash"])
                
                if file_size <= 0:
                    logger.error(f"Invalid file size: {file_size}")
                    return False
                    
                logger.info(f"Downloading file: {file_name} ({file_size} bytes)")
                
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                logger.error(f"Error parsing file metadata: {e}")
                return False
            
            # Determine save path
            if save_path is None:
                save_path = self.download_dir / file_name
            
            # Use temporary file during download
            temp_path = f"{save_path}.part"
            
            # Acknowledge readiness to receive file
            sock.send(b"OK: Ready to receive")
            
            # Receive file data
            received = 0
            start_time = time.time()
            file_data = bytearray()  # Store complete data for integrity verification
            
            with open(temp_path, 'wb') as f:
                sock.settimeout(30)  # Reset timeout for data transfer
                
                while received < file_size:
                    try:
                        # Calculate remaining bytes
                        remaining = file_size - received
                        chunk_size = min(4096, remaining)
                        
                        # Receive chunk
                        chunk = sock.recv(chunk_size)
                        
                        if not chunk:
                            logger.warning("Connection closed before download completed")
                            break
                        
                        # Write to file and add to buffer for verification
                        f.write(chunk)
                        file_data.extend(chunk)
                        received += len(chunk)
                        
                        # Progress reporting
                        now = time.time()
                        if now - start_time >= 1 or received == file_size:
                            progress = min(100, int(received * 100 / file_size))
                            speed = received / (now - start_time) / 1024 if now > start_time else 0
                            logger.info(f"Progress: {progress}% ({speed:.1f} KB/s)")
                            start_time = now
                        
                        # Send occasional acknowledgments to keep connection alive
                        if received % (1024*1024) == 0 and received < file_size:  # Every 1MB
                            sock.send(b"ACK")
                            
                    except socket.timeout:
                        logger.warning("Socket timeout during download, retrying...")
                        continue
                    except socket.error as e:
                        logger.error(f"Socket error: {e}")
                        return False
            
            # Verify we received the full file
            if received < file_size:
                logger.error(f"Incomplete download: {received}/{file_size} bytes")
                return False
            
            # Verify file integrity if hash was provided
            if file_hash:
                logger.info("Verifying file integrity...")
                if not crypto_utils.verify_file_hash(bytes(file_data), file_hash):
                    logger.error("File integrity verification failed!")
                    return False
                logger.info("File integrity verified successfully")
            
            # Finalize download by moving from temp file to final location
            os.replace(temp_path, save_path)
            logger.info(f"Download complete: {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False
            
        finally:
            # Clean up resources
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
    
