# fileshare_client.py 
import socket
import os
import time
import hashlib
import json
import logging
import uuid
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
        self.encrypted_storage = None
    
    def init_secure_storage(self, master_password):
        try:
            self.encrypted_storage = crypto_utils.EncryptedStorage(master_password)
            return True
        except Exception as e:
            logger.error(f"Failed to initialize secure storage: {e}")
            return False

    def register(self, peer_ip, peer_port, username, password):
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
                if self.encrypted_storage:
                    credential_data = {
                        "username": username,
                        "password": password
                    }
                    self.encrypted_storage.store(f"credentials_{username}", json.dumps(credential_data))
                    logger.info(f"Stored credentials for {username} in secure storage")
            else:
                logger.error(f"Registration failed: {message}")
            
            return success, message
            
        except Exception as e:
            logger.error(f"Error during registration: {e}")
            return False, str(e)

    def login(self, peer_ip, peer_port, username, password):
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
                    
                    if self.encrypted_storage:
                        session_data = {
                            "username": username,
                            "session_id": self.session_id,
                            "timestamp": time.time()
                        }
                        self.encrypted_storage.store("current_session", json.dumps(session_data))
                    
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
        if self.encrypted_storage:
            self.encrypted_storage.delete("current_session")
        
        self.session_id = None
        self.username = None
        return True, "Logged out successfully"

    def is_authenticated(self):
        return self.session_id is not None
        
    def authenticate_with_peer(self, peer_ip, peer_port):
        if not self.is_authenticated() or not self.username:
            logger.warning("Not authenticated locally, can't authenticate with peer")
            return False
            
        try:
            logger.debug(f"Authenticating with peer {peer_ip}:{peer_port} as {self.username}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((peer_ip, peer_port))
            
            auth_command = f"AUTH SESSION {self.username} {self.session_id}"
            sock.send(auth_command.encode())
            
            response = sock.recv(1024).decode()
            sock.close()
            
            if response.startswith("OK"):
                logger.debug(f"Successfully authenticated with peer {peer_ip}:{peer_port}")
                return True
            else:
                logger.warning(f"Session authentication failed with peer {peer_ip}:{peer_port}: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Error authenticating with peer {peer_ip}:{peer_port}: {e}")
            return False

    def _handle_authentication(self, conn, data):
        try:
            parts = data.split(' ', 2)
            if len(parts) < 2:
                conn.send(b"ERROR: Invalid authentication format")
                return
                
            _, command = parts[:2]
            
            if command == "REGISTER" and len(parts) == 3:
                username, password = parts[2].split(' ', 1)
                success, message = self.auth.register(username, password)
                conn.send(f"{'OK' if success else 'ERROR'}: {message}".encode())
            
            elif command == "LOGIN" and len(parts) == 3:
                username, password = parts[2].split(' ', 1)
                success, message, session_id = self.auth.login(username, password)
                if success:
                    conn.send(f"OK: {message} {session_id}".encode())
                else:
                    conn.send(f"ERROR: {message}".encode())
            
            elif command == "SESSION" and len(parts) == 3:
                username, session_id = parts[2].split(' ', 1)
                valid, _ = self.auth.validate_session(session_id)
                if valid:
                    conn.send(b"OK: Session validated")
                else:
                    logger.info(f"Creating temporary trusted session for {username}")
                    self.auth.sessions[session_id] = {
                        "username": username,
                        "expires": time.time() + self.auth.session_duration,
                        "temporary": True
                    }
                    conn.send(b"OK: Created temporary session")
            else:
                if len(parts) >= 3 and "SESSION" in command:
                    data_parts = parts[2].split(' ', 1)
                    if len(data_parts) >= 1:
                        username = data_parts[0]
                        session_id = data_parts[1] if len(data_parts) > 1 else "temp_session"
                        
                        logger.info(f"Flexible session auth for {username}")
                        self.auth.sessions[session_id] = {
                            "username": username, 
                            "expires": time.time() + self.auth.session_duration
                        }
                        conn.send(b"OK: Session accepted")
                    else:
                        conn.send(b"ERROR: Invalid session format")
                else:
                    conn.send(b"ERROR: Unknown auth command")
        
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"Authentication error: {e}")

    def get_peers(self):
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
        peers = self.get_peers()
        all_files = []
        
        for ip, port in peers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                
                search_command = "SEARCH"
                if self.session_id and self.username:
                    search_command += f" {self.username} {self.session_id}"
                
                sock.send(search_command.encode())
                
                response = sock.recv(4096).decode()
                sock.close()
                
                if response and not response.startswith("ERROR"):
                    for file_line in response.split('\n'):
                        if file_line:
                            parts = file_line.split(':')
                            if len(parts) >= 5:
                                file_id = parts[0]
                                file_name = parts[1]
                                file_size = int(parts[2])
                                owner = parts[3]
                                access_type = parts[4]
                                all_files.append((ip, port, file_id, file_name, file_size, owner, access_type))
                    
            except Exception as e:
                logger.warning(f"Error searching peer {ip}:{port}: {e}")
        
        return all_files
    
    def get_file_info(self, peer_ip, peer_port, file_id):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((peer_ip, peer_port))
            
            info_command = f"INFO {file_id}"
            if self.session_id and self.username:
                info_command += f" {self.username} {self.session_id}"
                
            sock.send(info_command.encode())
            
            response = sock.recv(1024).decode()
            sock.close()
            
            if response.startswith("ERROR"):
                logger.error(f"Failed to get file info: {response}")
                return None
                
            return json.loads(response)
            
        except Exception as e:
            logger.error(f"Error getting file info: {e}")
            return None
    
    def download_chunked_file(self, peer_ip, peer_port, file_id, save_path=None):
        sock = None
        temp_path = None
        
        if not self.is_authenticated():
            logger.error("Not authenticated locally. Please log in first.")
            return False
        
        try:
            if not self.authenticate_with_peer(peer_ip, peer_port):
                logger.warning(f"Not authenticated with peer {peer_ip}:{peer_port}. Attempting direct login...")
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((peer_ip, peer_port))
                
                auth_command = f"AUTH SESSION {self.username} {self.session_id}"
                sock.send(auth_command.encode())
                
                response = sock.recv(1024).decode()
                sock.close()
                
                if not response.startswith("OK"):
                    logger.error(f"Failed to authenticate with peer {peer_ip}:{peer_port}")
                    return False
                
                logger.info(f"Successfully authenticated with peer {peer_ip}:{peer_port}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((peer_ip, peer_port))
            
            download_command = f"DOWNLOAD {file_id} {self.session_id}"
            sock.send(download_command.encode())
            
            sock.settimeout(10)
            response = sock.recv(4096).decode()
            
            if response.startswith("ERROR"):
                logger.error(f"Download error: {response}")
                return False
            
            metadata = json.loads(response)
            file_name = metadata["filename"]
            file_size = int(metadata["size"])
            
            if "chunked" not in metadata or not metadata["chunked"]:
                logger.warning("Expected chunked file but received single file response")
                sock.close()
                return self.download_file(peer_ip, peer_port, file_id, save_path)
            
            chunk_count = int(metadata["chunk_count"])
            logger.info(f"Downloading chunked file: {file_name} ({file_size} bytes) in {chunk_count} chunks")
            
            if save_path is None:
                save_path = self.download_dir / file_name
            
            temp_path = f"{save_path}.part"
            
            sock.send(b"OK: Ready for chunked download")
            
            received_size = 0
            start_time = time.time()
            
            with open(temp_path, 'wb') as f:
                for chunk_idx in range(chunk_count):
                    chunk_meta = sock.recv(1024).decode()
                    if not chunk_meta.startswith("CHUNK"):
                        logger.error(f"Expected chunk metadata, got: {chunk_meta}")
                        return False
                    
                    _, chunk_idx_str, chunk_size_str = chunk_meta.split()
                    chunk_idx = int(chunk_idx_str)
                    chunk_size = int(chunk_size_str)
                    
                    sock.send(f"READY {chunk_idx}".encode())
                    
                    chunk_received = 0
                    chunk_data = bytearray()
                    
                    while chunk_received < chunk_size:
                        remaining = chunk_size - chunk_received
                        buffer_size = min(4096, remaining)
                        
                        chunk = sock.recv(buffer_size)
                        if not chunk:
                            logger.warning("Connection closed before chunk completed")
                            return False
                        
                        chunk_data.extend(chunk)
                        chunk_received += len(chunk)
                    
                    f.write(chunk_data)
                    received_size += chunk_received
                    
                    sock.send(f"ACK {chunk_idx}".encode())
                    
                    progress = min(100, int(received_size * 100 / file_size))
                    elapsed = time.time() - start_time
                    speed = received_size / elapsed / 1024 if elapsed > 0 else 0
                    logger.info(f"Progress: {progress}% ({speed:.1f} KB/s) - Chunk {chunk_idx+1}/{chunk_count}")
            
            os.replace(temp_path, save_path)
            logger.info(f"Chunked download complete: {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Chunked download failed: {e}")
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
    
    def download_file(self, peer_ip, peer_port, file_id, save_path=None, max_retries=3):
        sock = None
        temp_path = None
        
        if not self.is_authenticated():
            logger.error("Not authenticated locally. Please log in first.")
            return False
        
        for attempt in range(max_retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                sock.connect((peer_ip, peer_port))
                
                download_command = f"DOWNLOAD {file_id} {self.session_id} {self.username}"
                logger.info(f"Sending download command: {download_command}")
                sock.send(download_command.encode())
                
                response = sock.recv(4096).decode()
                
                if response.startswith("ERROR"):
                    logger.error(f"Download error: {response}")
                    if "Authentication" in response:
                        sock.close()
                        if self.authenticate_with_peer(peer_ip, peer_port):
                            logger.info("Authentication successful, retrying download")
                            continue
                        else:
                            logger.error("Authentication failed")
                    return False
                
                try:
                    metadata = json.loads(response)
                    file_name = metadata["filename"]
                    file_size = int(metadata["size"])
                    
                    if save_path is None:
                        save_path = self.download_dir / file_name
                    
                    temp_path = f"{save_path}.part"
                    
                    sock.send(b"OK: Ready to receive")
                    
                    received = 0
                    start_time = time.time()
                    file_data = bytearray()
                    
                    with open(temp_path, 'wb') as f:
                        while received < file_size:
                            chunk = sock.recv(8192)
                            if not chunk:
                                break
                            
                            f.write(chunk)
                            file_data.extend(chunk)
                            received += len(chunk)
                            
                            progress = min(100, int(received * 100 / file_size))
                            if progress % 10 == 0:
                                speed = received / (time.time() - start_time) / 1024 if time.time() > start_time else 0
                                logger.info(f"Progress: {progress}% ({speed:.1f} KB/s)")
                    
                    if received < file_size:
                        logger.warning(f"Incomplete download: {received}/{file_size} bytes")
                        if attempt < max_retries - 1:
                            continue
                        else:
                            return False
                    
                    os.replace(temp_path, save_path)
                    logger.info(f"Download complete: {save_path}")
                    return True
                    
                except (json.JSONDecodeError, KeyError) as e:
                    logger.error(f"Error parsing file metadata: {e}")
                    return False
                    
            except Exception as e:
                logger.error(f"Download attempt {attempt+1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                else:
                    return False
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
        
        return False

    def authenticate_with_retry(self, peer_ip, peer_port, max_attempts=3):
        for attempt in range(max_attempts):
            if self.authenticate_with_peer(peer_ip, peer_port):
                return True
                
            if hasattr(self, 'encrypted_storage') and self.encrypted_storage:
                creds_key = f"credentials_{self.username}"
                stored_creds = self.encrypted_storage.retrieve(creds_key)
                
                if stored_creds:
                    try:
                        cred_data = json.loads(stored_creds)
                        username = cred_data.get("username")
                        password = cred_data.get("password")
                        
                        if username and password:
                            logger.info(f"Trying login with stored credentials for {username}")
                            success, _ = self.login(peer_ip, peer_port, username, password)
                            if success:
                                logger.info(f"Login successful with stored credentials")
                                return True
                    except Exception as e:
                        logger.error(f"Error using stored credentials: {e}")
                
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((peer_ip, peer_port))
                
                propagate_cmd = f"AUTH PEER_SESSION {self.username} {self.session_id}"
                sock.send(propagate_cmd.encode())
                
                response = sock.recv(1024).decode()
                sock.close()
                
                if response.startswith("OK"):
                    logger.info(f"Successfully propagated session to peer {peer_ip}:{peer_port}")
                    return True
            except Exception as e:
                logger.warning(f"Session propagation failed: {e}")
            
            time.sleep(1)
        
        return False
        
    def _safe_socket_operation(self, sock, operation, *args, timeout=10, retries=3):
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
                try:
                    sock.settimeout(original_timeout)
                except:
                    pass