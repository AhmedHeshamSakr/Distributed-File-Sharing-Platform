# fileshare_peer.py
import socket
import threading
import os
import uuid
import time
import json
import logging
from pathlib import Path
from user_auth import UserAuth
import crypto_utils
from crypto_utils import KeyManager
from fileshare_client import FileShareClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('FileSharePeer')

class FileSharePeer:
    def __init__(self, host, port, rendezvous_host, rendezvous_port):
        self.host, self.port = host, port
        self.rendezvous = (rendezvous_host, rendezvous_port)
        self.shared_files = {}
        self.shared_dir = Path("shared")
        self.shared_dir.mkdir(exist_ok=True)
        
        self.auth = UserAuth()
        self.user_session = None
        self.current_username = None
        
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.key_manager = KeyManager()
        self.active_transfers = {}
        self.lock = threading.Lock()
        self.running = True
        self.client = FileShareClient(rendezvous_host, rendezvous_port)
        
        self.chunk_size = 1024 * 1024  # 1MB chunks

    def start(self):
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        self._register_with_rendezvous()
        threading.Thread(target=self._heartbeat_thread, daemon=True).start()
        threading.Thread(target=self._session_cleanup_thread, daemon=True).start()
        self._load_shared_files()
        logger.info(f"Peer running on {self.host}:{self.port}")
        try:
            while self.running:
                self.server.settimeout(1.0)
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
        while self.running:
            try:
                time.sleep(60)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect(self.rendezvous)
                sock.send(b"HEARTBEAT")
                sock.recv(1024)
                sock.close()
                
                logger.debug("Sent heartbeat to rendezvous server")
            except Exception as e:
                logger.warning(f"Failed to send heartbeat: {e}")
    
    def _session_cleanup_thread(self):
        while self.running:
            time.sleep(300)
            self.auth.cleanup_sessions()
    
    def _load_shared_files(self):
        metadata_path = self.shared_dir / "metadata.json"
        if metadata_path.exists():
            try:
                with open(metadata_path, 'r') as f:
                    self.shared_files = json.load(f)
                logger.info(f"Loaded {len(self.shared_files)} shared files from metadata")
            except Exception as e:
                logger.error(f"Failed to load shared files metadata: {e}")
    
    def _save_shared_files(self):
        metadata_path = self.shared_dir / "metadata.json"
        try:
            with open(metadata_path, 'w') as f:
                json.dump(self.shared_files, f)
            logger.info(f"Saved metadata for {len(self.shared_files)} files")
        except Exception as e:
            logger.error(f"Failed to save shared files metadata: {e}")

    def update_shared_with_me(self):
        if not self.is_authenticated():
            logger.warning("Must be authenticated to update shared files list")
            return {}
        
        logger.info(f"Looking for files shared with user: {self.current_username} (Session: {self.user_session})")
        shared_with_me = {}
        peers = self.get_peers_from_rendezvous()
        logger.info(f"Found {len(peers)} peers to query")
        
        successful_peers = 0
        for peer_ip, peer_port in peers:
            if peer_ip == self.host and peer_port == self.port:
                continue
            
            logger.info(f"Checking peer {peer_ip}:{peer_port} for shared files")
            try:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((peer_ip, peer_port))
                    
                    request = f"SHARED_WITH {self.current_username} {self.user_session}"
                    logger.info(f"Sending request: {request}")
                    sock.send(request.encode())
                    
                    response = sock.recv(4096).decode()
                    logger.info(f"Got response from {peer_ip}:{peer_port}: {len(response)} bytes")
                    
                    if response and not response.startswith("ERROR"):
                        file_count = 0
                        for file_line in response.split('\n'):
                            if file_line:
                                try:
                                    parts = file_line.split(':')
                                    if len(parts) >= 5:
                                        file_id = parts[0]
                                        file_name = parts[1]
                                        file_size = int(parts[2])
                                        owner = parts[3]
                                        
                                        shared_with_me[file_id] = {
                                            "name": file_name,
                                            "size": file_size,
                                            "owner": owner,
                                            "peer_ip": peer_ip,
                                            "peer_port": peer_port
                                        }
                                        file_count += 1
                                    else:
                                        logger.warning(f"Invalid file line format: {file_line}")
                                except Exception as e:
                                    logger.error(f"Error parsing file line: {file_line} - {e}")
                        
                        logger.info(f"Found {file_count} files shared with me from peer {peer_ip}:{peer_port}")
                        successful_peers += 1
                    elif response.startswith("ERROR"):
                        logger.error(f"Error from peer {peer_ip}:{peer_port}: {response}")
                    else:
                        logger.warning(f"Empty response from peer {peer_ip}:{peer_port}")
                finally:
                    if sock:
                        sock.close()
                                
            except ConnectionRefusedError:
                logger.warning(f"Connection refused by peer {peer_ip}:{peer_port} - peer may be offline")
            except socket.timeout:
                logger.warning(f"Connection timeout with peer {peer_ip}:{peer_port}")
            except Exception as e:
                logger.error(f"Error getting shared files from {peer_ip}:{peer_port}: {e}")
        
        logger.info(f"Successfully queried {successful_peers} peers, found {len(shared_with_me)} files shared with {self.current_username}")
        self.files_shared_with_me = shared_with_me
        return shared_with_me

    def handle_request(self, conn, addr):
        try:
            conn.settimeout(30)
            data = conn.recv(1024).decode()
            
            if data.startswith("UPLOAD"):
                self._handle_upload(conn, data)
            elif data.startswith("SEARCH"):
                self._handle_search(conn, data)
            elif data.startswith("DOWNLOAD"):
                self._handle_download(conn, data)
            elif data.startswith("INFO"):
                self._handle_file_info(conn, data)
            elif data.startswith("AUTH"):
                self._handle_authentication(conn, data)
            elif data.startswith("SYNC"):
                self.handle_user_sync(conn, data)
            elif data.startswith("SHARED_WITH"):
                self.handle_shared_with(conn, data)
            else:
                conn.send(b"ERROR: Invalid command")
                logger.warning(f"Invalid command from {addr}: {data}")
        except Exception as e:
            logger.error(f"Error handling request from {addr}: {e}")
        finally:
            conn.close()

    def handle_shared_with(self, conn, data):
        try:
            parts = data.split()
            if len(parts) < 3:
                conn.send(b"ERROR: Invalid request format")
                return
                
            _, username, session_id = parts
            logger.info(f"Received shared_with request for user: {username} with session {session_id[:8]}...")
            
            valid, verified_username = self.auth.validate_session(session_id)
            
            if not valid:
                logger.info(f"Creating temporary session for remote user {username}")
                self.auth.sessions[session_id] = {
                    "username": username,
                    "expires": time.time() + self.auth.session_duration,
                    "synced": True
                }
                valid = True
                verified_username = username
            
            if not valid or verified_username != username:
                error_msg = f"ERROR: Authentication failed for {username}"
                logger.error(error_msg)
                conn.send(error_msg.encode())
                return
            
            shared_files = []
            
            for file_id, info in self.shared_files.items():
                file_owner = info.get("owner", "")
                allowed_users = info.get("allowed_users", [])
                
                if file_owner == username:
                    continue
                    
                if not allowed_users or username in allowed_users:
                    access_type = "private" if allowed_users else "public"
                    file_str = f"{file_id}:{info['name']}:{info['size']}:{file_owner}:{access_type}"
                    shared_files.append(file_str)
                    logger.info(f"File {file_id} shared with user {username}: {info['name']}")
            
            response = '\n'.join(shared_files)
            conn.send(response.encode())
            
            logger.info(f"Sent {len(shared_files)} shared files to user {username}")
            
        except Exception as e:
            error_msg = f"ERROR: {str(e)}"
            logger.error(f"Error handling shared_with request: {e}")
            try:
                conn.send(error_msg.encode())
            except:
                pass

    def _handle_authentication(self, conn, data):
        try:
            parts = data.split(' ', 2)
            if len(parts) < 3:
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
                    conn.send(b"ERROR: Invalid session")
            
            else:
                conn.send(b"ERROR: Unknown auth command")
        
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"Authentication error: {e}")

    def handle_user_sync(self, conn, data):
        try:
            parts = data.split(' ', 2)
            if len(parts) < 3:
                conn.send(b"ERROR: Invalid sync format")
                return
                
            _, command, payload = parts
            
            if command == "REGISTER":
                username, password_hash_data = payload.split(':', 1)
                success, message = self.auth.add_remote_user(username, password_hash_data)
                conn.send(f"{'OK' if success else 'ERROR'}: {message}".encode())
                
            elif command == "GET":
                username = payload
                user_data = self.auth.get_user_data(username)
                if user_data:
                    response = json.dumps(user_data)
                    conn.send(response.encode())
                else:
                    conn.send(b"ERROR: User not found")
            
            elif command == "VALIDATE_SESSION":
                username, session_id = payload.split(':', 1)
                
                valid, _ = self.auth.validate_session(session_id)
                if valid:
                    conn.send(b"OK: Session is valid")
                    return
                
                new_session_id = str(uuid.uuid4())
                self.auth.sessions[new_session_id] = {
                    "username": username,
                    "expires": time.time() + self.auth.session_duration,
                    "synced": True
                }
                
                conn.send(f"OK: Created temporary session {new_session_id}".encode())
                    
            else:
                conn.send(b"ERROR: Unknown sync command")
                
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"User sync error: {e}")

    def _handle_download(self, conn, data):
        try:
            parts = data.split()
            if len(parts) < 2:
                conn.send(b"ERROR: Invalid download format")
                return
            
            file_id = parts[1]
            session_id = parts[2] if len(parts) >= 3 else None
            username = None
            
            if file_id not in self.shared_files:
                conn.send(b"ERROR: File not found")
                return
                    
            file_info = self.shared_files[file_id]
            
            valid = False
            if session_id:
                valid, username = self.auth.validate_session(session_id)
            
            if not valid and session_id:
                if len(parts) >= 4:
                    username = parts[3]
                
                if not username and ':' in session_id:
                    username_part, _ = session_id.split(':', 1)
                    if username_part:
                        username = username_part
                
                if not username:
                    username = "anonymous_user"
                    
                logger.info(f"Creating temporary download session for {username}")
                self.auth.sessions[session_id] = {
                    "username": username,
                    "expires": time.time() + 300,
                    "temporary": True
                }
                valid = True
            
            if not valid or not username:
                allowed_users = file_info.get("allowed_users", [])
                if allowed_users:
                    conn.send(b"ERROR: Authentication required")
                    return
                else:
                    username = "anonymous_user"
            
            file_owner = file_info.get("owner", "")
            allowed_users = file_info.get("allowed_users", [])
            
            if allowed_users and username not in allowed_users:
                conn.send(b"ERROR: This file is not shared with you")
                return
            
            logger.info(f"User {username} downloading file {file_id} from owner {file_owner}")
            
            if "chunked" in file_info and file_info["chunked"]:
                self._handle_chunked_download(conn, file_id, username)
            else:
                self._handle_single_file_download(conn, file_id, username)
                
        except Exception as e:
            try:
                conn.send(f"ERROR: {str(e)}".encode())
            except:
                pass
            logger.error(f"Download error: {e}")
            
    def _handle_single_file_download(self, conn, file_id, username):
        try:
            file_info = self.shared_files[file_id]
            file_path = file_info["path"]
            
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            logger.debug(f"Read encrypted file: {len(encrypted_data)} bytes")
            
            encryption_key = self.key_manager.get_encryption_key(file_id)
            
            decrypted_data = crypto_utils.decrypt_data(encrypted_data, encryption_key)
            logger.debug(f"Successfully decrypted to {len(decrypted_data)} bytes")
            
            if "hash" in file_info:
                expected_hash = crypto_utils.decode_bytes(file_info["hash"])
                if not crypto_utils.verify_file_hash(decrypted_data, expected_hash):
                    logger.error(f"Integrity verification failed for file {file_id}")
                    conn.send(b"ERROR: File integrity check failed")
                    return
                logger.debug(f"File integrity verified for {file_id}")
                
        except Exception as e:
            error_message = f"Decryption failed - {str(e)}"
            logger.error(f"File {file_id}: {error_message}")
            conn.send(f"ERROR: {error_message}".encode())
            return
        
        header = json.dumps({
            "filename": file_info['name'],
            "size": len(decrypted_data),
            "hash": file_info.get("hash")
        }).encode()
        conn.send(header)
        
        conn.settimeout(10)
        try:
            response = conn.recv(1024).decode()
            if not response.startswith("OK"):
                logger.warning(f"Client rejected download: {response}")
                return
        except socket.timeout:
            logger.error("Timeout waiting for client acknowledgment")
            return
        
        sent = 0
        data_len = len(decrypted_data)
        
        while sent < data_len:
            chunk_size = min(4096, data_len - sent)
            chunk = decrypted_data[sent:sent+chunk_size]
            
            try:
                conn.settimeout(30)
                conn.sendall(chunk)
                sent += len(chunk)
            except socket.error as e:
                logger.error(f"Socket error while sending file: {e}")
                return
        
        logger.info(f"File {file_id} downloaded by {username}: {sent} bytes (decrypted)")

    def _handle_search(self, conn, data):
        try:
            parts = data.split()
            authenticated = False
            username = None
            
            if len(parts) >= 3:
                _, username, session_id = parts
                valid, username = self.auth.validate_session(session_id)
                authenticated = valid
                logger.debug(f"Search request from authenticated user: {username}")
            else:
                logger.debug("Search request from unauthenticated user")
            
            visible_files = []
            
            for file_id, info in self.shared_files.items():
                file_owner = info.get("owner", "")
                allowed_users = info.get("allowed_users", [])
                
                can_see_file = False
                
                if authenticated:
                    if file_owner != username:
                        if not allowed_users:
                            can_see_file = True
                        elif username in allowed_users:
                            can_see_file = True
                else:
                    if not allowed_users:
                        can_see_file = True
                
                if can_see_file:
                    access_type = "private" if allowed_users else "public"
                    file_str = f"{file_id}:{info['name']}:{info['size']}:{file_owner}:{access_type}"
                    visible_files.append(file_str)
                    
                    logger.debug(f"File {file_id} visible to user {username}: {info['name']}")
            
            response = '\n'.join(visible_files)
            conn.send(response.encode())
            
            logger.info(f"Search results: {len(visible_files)} files visible to user {username if authenticated else 'anonymous'}")
            
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"Search error: {e}")
    
    def _handle_file_info(self, conn, data):
        try:
            parts = data.split()
            if len(parts) < 2:
                conn.send(b"ERROR: Invalid info request")
                return
                    
            authenticated = False
            username = None
            file_id = parts[1]
            
            if len(parts) >= 4:
                username, session_id = parts[2:4]
                valid, validated_username = self.auth.validate_session(session_id)
                if valid:
                    authenticated = True
                    username = validated_username
                else:
                    self.auth.sessions[session_id] = {
                        "username": username,
                        "expires": time.time() + 300,
                        "temporary": True
                    }
                    authenticated = True
            
            if file_id in self.shared_files:
                info = self.shared_files[file_id]
                
                allowed_users = info.get("allowed_users", [])
                
                if authenticated or not allowed_users:
                    response = json.dumps({
                        "name": info["name"],
                        "size": info["size"],
                        "owner": info.get("owner", "unknown"),
                        "chunked": info.get("chunked", False),
                        "chunk_count": info.get("chunk_count", 0),
                        "access_type": "restricted" if allowed_users else "public",
                        "allowed_users": allowed_users if authenticated else []
                    })
                    conn.send(response.encode())
                else:
                    conn.send(b"ERROR: Access denied for this file")
            else:
                conn.send(b"ERROR: File not found")
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"File info error: {e}")

    def _handle_upload(self, conn, data):
        temp_path = None
        
        try:
            parts = data.split(' ', 3)
            if len(parts) != 4:
                conn.send(b"ERROR: Invalid upload format")
                return
                    
            _, file_name, file_size_str, session_id = parts
            
            valid, username = self.auth.validate_session(session_id)
            if not valid:
                conn.send(b"ERROR: Authentication required")
                return
                    
            file_size = int(file_size_str)
            
            file_id = str(uuid.uuid4())
            temp_path = self.shared_dir / f"{file_id}.temp"
            dest_path = self.shared_dir / file_id
            
            conn.send(f"OK: {file_id}".encode())
            
            received = 0
            file_data = bytearray()
            
            with open(temp_path, 'wb') as f:
                while received < file_size:
                    chunk = conn.recv(min(4096, file_size - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    file_data.extend(chunk)
                    received += len(chunk)
            
            if received != file_size:
                conn.send(b"ERROR: Incomplete upload")
                os.remove(temp_path)
                return
            
            encryption_key = self.key_manager.get_encryption_key(file_id)
            
            encrypted_data = crypto_utils.encrypt_data(bytes(file_data), encryption_key)
            
            with open(dest_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.shared_files[file_id] = {
                "name": file_name,
                "path": str(dest_path),
                "size": file_size,
                "owner": username,
                "hash": crypto_utils.encode_bytes(crypto_utils.compute_file_hash(file_data)),
                "allowed_users": []
            }
            
            self._save_shared_files()
            conn.send(b"SUCCESS: Upload complete")
            
        except Exception as e:
            logger.error(f"Upload error: {e}")
            try:
                conn.send(f"ERROR: {str(e)}".encode())
            except:
                pass
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
    
    def share_file(self, filepath):
        if not self.is_authenticated():
            logger.error("Authentication required to share files")
            return None, "Authentication required"
            
        try:
            if not os.path.exists(filepath):
                logger.error(f"File not found: {filepath}")
                return None, "File not found"
                
            file_size = os.path.getsize(filepath)
            file_name = os.path.basename(filepath)
            
            if file_size > 10 * 1024 * 1024:
                return self.share_file_chunked(filepath)
            
            file_id = str(uuid.uuid4())
            dest_path = self.shared_dir / file_id
            
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            file_hash = crypto_utils.compute_file_hash(file_data)
            
            encryption_key = self.key_manager.get_encryption_key(file_id)
            
            encrypted_data = crypto_utils.encrypt_data(file_data, encryption_key)
            
            with open(dest_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.shared_files[file_id] = {
                "name": file_name,
                "path": str(dest_path),
                "size": file_size,
                "owner": self.current_username,
                "hash": crypto_utils.encode_bytes(file_hash),
                "allowed_users": []
            }
            
            self._save_shared_files()
            
            logger.info(f"Shared file: {file_name} ({file_size} bytes), ID: {file_id}")
            return file_id, "File shared successfully"
                
        except Exception as e:
            logger.error(f"Error sharing file: {e}")
            return None, f"Error: {str(e)}"

    def share_file_chunked(self, filepath):
        if not self.is_authenticated():
            logger.error("Authentication required to share files")
            return None, "Authentication required"
            
        try:
            if not os.path.exists(filepath):
                logger.error(f"File not found: {filepath}")
                return None, "File not found"
                
            file_size = os.path.getsize(filepath)
            file_name = os.path.basename(filepath)
            
            file_id = str(uuid.uuid4())
            chunks_dir = self.shared_dir / file_id
            chunks_dir.mkdir(exist_ok=True)
            
            chunk_idx = 0
            chunk_hashes = []
            
            with open(filepath, 'rb') as src_file:
                while True:
                    chunk_data = src_file.read(self.chunk_size)
                    if not chunk_data:
                        break
                    
                    chunk_hash = crypto_utils.compute_file_hash(chunk_data)
                    chunk_hashes.append(crypto_utils.encode_bytes(chunk_hash))
                    
                    encryption_key = self.key_manager.get_encryption_key(file_id)
                    
                    encrypted_chunk = crypto_utils.encrypt_data(chunk_data, encryption_key)
                    
                    chunk_path = chunks_dir / f"chunk_{chunk_idx}"
                    with open(chunk_path, 'wb') as chunk_file:
                        chunk_file.write(encrypted_chunk)
                    
                    chunk_idx += 1
                    
                    if chunk_idx % 10 == 0:
                        progress = min(100, int(src_file.tell() * 100 / file_size))
                        logger.info(f"Processing file chunks: {progress}% ({chunk_idx} chunks)")
            
            self.shared_files[file_id] = {
                "name": file_name,
                "path": str(chunks_dir),
                "size": file_size,
                "owner": self.current_username,
                "chunked": True,
                "chunk_count": chunk_idx,
                "chunk_hashes": chunk_hashes,
                "allowed_users": []
            }
            
            self._save_shared_files()
            
            logger.info(f"Shared chunked file: {file_name} ({file_size} bytes) in {chunk_idx} chunks, ID: {file_id}")
            return file_id, "File shared successfully"
                
        except Exception as e:
            logger.error(f"Error sharing file: {e}")
            return None, f"Error: {str(e)}"
    
    def share_file_with_users(self, filepath, allowed_users=None):
        file_id, message = self.share_file(filepath)
        
        if not file_id:
            return None, message
        
        if allowed_users:
            try:
                self.shared_files[file_id]["allowed_users"] = allowed_users
                self._save_shared_files()
                logger.info(f"File {file_id} access restricted to users: {', '.join(allowed_users)}")
                return file_id, "File shared successfully with restricted access"
            except Exception as e:
                logger.error(f"Error setting file permissions: {e}")
                return file_id, f"File shared, but permission setup failed: {str(e)}"
        
        return file_id, message

    def get_peers_from_rendezvous(self):
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
            
            return peers
                
        except Exception as e:
            logger.error(f"Error getting peers from rendezvous: {e}")
            return []
    
    def register_user(self, username, password):
        success, message = self.auth.register(username, password)
        
        if success:
            user_data = self.auth.get_user_data(username)
            if user_data:
                user_data_json = json.dumps(user_data)
                
                peers = self.client.get_peers() if hasattr(self, 'client') else []
                for peer_ip, peer_port in peers:
                    try:
                        if peer_ip == self.host and peer_port == self.port:
                            continue
                            
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5)
                        sock.connect((peer_ip, peer_port))
                        sock.send(f"SYNC REGISTER {username}:{user_data_json}".encode())
                        response = sock.recv(1024).decode()
                        sock.close()
                        
                        logger.info(f"User sync to {peer_ip}:{peer_port}: {response}")
                    except Exception as e:
                        logger.error(f"Failed to sync user to {peer_ip}:{peer_port}: {e}")
                    
        return success, message
    
    def login_user(self, username, password):
        success, message, session_id = self.auth.login(username, password)
        if success:
            self.user_session = session_id
            self.current_username = username
        return success, message
    
    def logout_user(self):
        if self.user_session:
            result, message = self.auth.logout(self.user_session)
            self.user_session = None
            self.current_username = None
            return result, message
        return False, "No active session"
    
    def is_authenticated(self):
        if not self.user_session:
            return False
        valid, username = self.auth.validate_session(self.user_session)
        if valid:
            self.current_username = username
            return True
        else:
            self.user_session = None
            self.current_username = None
            return False
        