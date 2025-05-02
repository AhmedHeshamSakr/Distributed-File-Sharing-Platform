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
        self.shared_files = {}  # {file_id: {name, path, size, owner}}
        self.shared_dir = Path("shared")
        self.shared_dir.mkdir(exist_ok=True)
        
        # User authentication
        self.auth = UserAuth()
        self.user_session = None  # Current user session
        self.current_username = None  # Current logged in username
        
        # Create server socket
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.key_manager = KeyManager()
        # Keep track of active transfers
        self.active_transfers = {}
        self.lock = threading.Lock()
        self.running = True
        self.client = FileShareClient(rendezvous_host, rendezvous_port)

    
    def start(self):
        """Start the peer server and register with rendezvous"""
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        # Register with rendezvous server
        self._register_with_rendezvous()
        # Start heartbeat thread
        threading.Thread(target=self._heartbeat_thread, daemon=True).start()
        # Start session cleanup thread
        threading.Thread(target=self._session_cleanup_thread, daemon=True).start()
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
    
    def _session_cleanup_thread(self):
        """Periodically clean up expired sessions"""
        while self.running:
            time.sleep(300)  # Clean up every 5 minutes
            self.auth.cleanup_sessions()
    
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
            elif data.startswith("AUTH"):
                self._handle_authentication(conn, data)
            elif data.startswith("SYNC"):
                self.handle_user_sync(conn, data)
            else:
                conn.send(b"ERROR: Invalid command")
                logger.warning(f"Invalid command from {addr}: {data}")
        except Exception as e:
            logger.error(f"Error handling request from {addr}: {e}")
        finally:
            conn.close()
    
    def _handle_authentication(self, conn, data):
        """Handle authentication requests (for remote API access)"""
        try:
            parts = data.split(' ', 2)  # Changed to handle SESSION auth type
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
                # Handle session-based authentication
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
        """Handle user synchronization requests"""
        try:
            parts = data.split(' ', 2)
            if len(parts) < 3:
                conn.send(b"ERROR: Invalid sync format")
                return
                
            _, command, payload = parts
            
            if command == "REGISTER":
                # Format: "SYNC REGISTER username:password_hash"
                username, password_hash = payload.split(':', 1)
                success, message = self.auth.add_remote_user(username, password_hash)
                conn.send(f"{'OK' if success else 'ERROR'}: {message}".encode())
                
            elif command == "GET":
                # Format: "SYNC GET username"
                username = payload
                user_data = self.auth.get_user_data(username)
                if user_data:
                    response = json.dumps(user_data)
                    conn.send(response.encode())
                else:
                    conn.send(b"ERROR: User not found")
                    
            else:
                conn.send(b"ERROR: Unknown sync command")
                
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"User sync error: {e}")


    def _handle_user_sync(self, conn, data):
        """Handle user synchronization including sessions"""
        try:
            parts = data.split(' ', 2)
            if len(parts) < 3:
                conn.send(b"ERROR: Invalid sync format")
                return
                
            _, command, payload = parts
            
            if command == "VALIDATE_SESSION":
                # Format: "SYNC VALIDATE_SESSION username:session_id"
                username, session_id = payload.split(':', 1)
                
                # First check if we have this session locally
                valid, _ = self.auth.validate_session(session_id)
                if valid:
                    conn.send(b"OK: Session is valid")
                    return
                
                # If not valid locally, we'll create a temporary session
                # This is a simplified approach - in a real system you'd want more security
                new_session_id = str(uuid.uuid4())
                self.auth.sessions[new_session_id] = {
                    "username": username,
                    "expires": time.time() + self.auth.session_duration,
                    "synced": True  # Mark as synced from another peer
                }
                
                conn.send(f"OK: Created temporary session {new_session_id}".encode())
                
            else:
                conn.send(b"ERROR: Unknown sync command")
                
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"User sync error: {e}")




    def _handle_download(self, conn, data):
        """Handle file download request"""
        try:
            parts = data.split()
            if len(parts) < 3:
                conn.send(b"ERROR: Invalid download format")
                return
            
            _, file_id, session_id = parts
            
            # Verify session
            valid, username = self.auth.validate_session(session_id)
            if not valid:
                conn.send(b"ERROR: Authentication required")
                return
            
            if file_id not in self.shared_files:
                conn.send(b"ERROR: File not found")
                return
                    
            file_info = self.shared_files[file_id]
            file_path = file_info["path"]
            
            try:
                # Read the entire encrypted file
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                logger.debug(f"Read encrypted file: {len(encrypted_data)} bytes")
                
                # Get the encryption key for this file
                encryption_key = self.key_manager.get_encryption_key(file_id)
                
                # Decrypt the file
                decrypted_data = crypto_utils.decrypt_data(encrypted_data, encryption_key)
                logger.debug(f"Successfully decrypted to {len(decrypted_data)} bytes")
                
                # Verify integrity if hash is available
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
            
            # Send file metadata
            header = json.dumps({
                "filename": file_info['name'],
                "size": len(decrypted_data),
                "hash": file_info.get("hash")
            }).encode()
            conn.send(header)
            
            # Wait for client acknowledgment
            conn.settimeout(10)
            try:
                response = conn.recv(1024).decode()
                if not response.startswith("OK"):
                    logger.warning(f"Client rejected download: {response}")
                    return
            except socket.timeout:
                logger.error("Timeout waiting for client acknowledgment")
                return
            
            # Send the decrypted file in chunks
            sent = 0
            data_len = len(decrypted_data)
            
            while sent < data_len:
                # Determine chunk size
                chunk_size = min(4096, data_len - sent)
                
                # Get chunk from decrypted data
                chunk = decrypted_data[sent:sent+chunk_size]
                
                # Send chunk
                try:
                    conn.settimeout(30)
                    conn.sendall(chunk)
                    sent += len(chunk)
                except socket.error as e:
                    logger.error(f"Socket error while sending file: {e}")
                    return
            
            logger.info(f"File {file_id} downloaded by {username}: {sent} bytes (decrypted)")
        
        except Exception as e:
            try:
                conn.send(f"ERROR: {str(e)}".encode())
            except:
                pass
            logger.error(f"Download error: {e}")

    def _handle_search(self, conn):
        """Handle search request for available files"""
        try:
            # Format: file_id:name:size:owner
            files = []
            for fid, info in self.shared_files.items():
                file_str = f"{fid}:{info['name']}:{info['size']}:{info.get('owner', 'unknown')}"
                files.append(file_str)
            
            conn.send('\n'.join(files).encode())
            logger.debug(f"Sent information about {len(files)} files")
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"Search error: {e}")
    
    def _handle_file_info(self, conn, data):
        """Handle request for detailed information about a specific file"""
        try:
            parts = data.split()
            if len(parts) < 2:
                conn.send(b"ERROR: Invalid info request")
                return
                
            _, file_id = parts[:2]
            
            if file_id in self.shared_files:
                info = self.shared_files[file_id]
                response = json.dumps({
                    "name": info["name"],
                    "size": info["size"],
                    "owner": info.get("owner", "unknown")
                })
                conn.send(response.encode())
            else:
                conn.send(b"ERROR: File not found")
        except Exception as e:
            conn.send(f"ERROR: {str(e)}".encode())
            logger.error(f"File info error: {e}")

   # Then modify the _handle_upload method to include encryption and hashing
    def _handle_upload(self, conn, data):
        """Handle file upload from another peer"""
        temp_path = None
        
        try:
            parts = data.split(' ', 3)
            if len(parts) != 4:
                conn.send(b"ERROR: Invalid upload format")
                return
                    
            _, file_name, file_size_str, session_id = parts
            
            # Verify session
            valid, username = self.auth.validate_session(session_id)
            if not valid:
                conn.send(b"ERROR: Authentication required")
                return
                    
            file_size = int(file_size_str)
            
            # Generate file ID and prepare destination paths
            file_id = str(uuid.uuid4())
            temp_path = self.shared_dir / f"{file_id}.temp"
            dest_path = self.shared_dir / file_id
            
            # Acknowledge and prepare for upload
            conn.send(f"OK: {file_id}".encode())
            
            # Receive file in chunks and ensure complete transfer
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
            
            # Verify completeness
            if received != file_size:
                conn.send(b"ERROR: Incomplete upload")
                os.remove(temp_path)
                return
            
            # Get encryption key
            encryption_key = self.key_manager.get_encryption_key(file_id)
            
            # Encrypt the file data
            encrypted_data = crypto_utils.encrypt_data(bytes(file_data), encryption_key)
            
            # Write encrypted data to final destination
            with open(dest_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Store metadata
            self.shared_files[file_id] = {
                "name": file_name,
                "path": str(dest_path),
                "size": file_size,
                "owner": username,
                "hash": crypto_utils.encode_bytes(crypto_utils.compute_file_hash(file_data))
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
        """Share a local file (utility method for integration)"""
        # Check if user is authenticated
        if not self.user_session:
            logger.error("Authentication required to share files")
            return None, "Authentication required"
            
        try:
            if not os.path.exists(filepath):
                logger.error(f"File not found: {filepath}")
                return None, "File not found"
                
            # Calculate file size
            file_size = os.path.getsize(filepath)
            file_name = os.path.basename(filepath)
            
            # Generate file ID and copy to shared directory
            file_id = str(uuid.uuid4())
            dest_path = self.shared_dir / file_id
            
            # Copy file in binary mode to preserve exact contents
            with open(filepath, 'rb') as src, open(dest_path, 'wb') as dst:
                # Copy in chunks to handle large files
                chunk = src.read(8192)
                while chunk:
                    dst.write(chunk)
                    chunk = src.read(8192)
            
            # Store metadata
            self.shared_files[file_id] = {
                "name": file_name,
                "path": str(dest_path),
                "size": file_size,
                "owner": self.current_username
            }
            
            # Save metadata
            self._save_shared_files()
            
            logger.info(f"Shared file: {file_name} ({file_size} bytes), ID: {file_id}")
            return file_id, "File shared successfully"
                
        except Exception as e:
            logger.error(f"Error sharing file: {e}")
            return None, f"Error: {str(e)}"

    def get_peers_from_rendezvous(self):
        """Get list of peers from rendezvous server"""
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
            
            return peers
                
        except Exception as e:
            logger.error(f"Error getting peers from rendezvous: {e}")
            return []
    
    # User authentication methods
    def register_user(self, username, password):
        """Register a new user and sync to other peers"""
        success, message = self.auth.register(username, password)
        
        if success:
            # Get the password hash to share with other peers
            password_hash = self.auth.users[username]["password_hash"]
            
            # Sync this user to all other peers
            peers = self.client.get_peers() if hasattr(self, 'client') else []
            for peer_ip, peer_port in peers:
                try:
                    if peer_ip == self.host and peer_port == self.port:
                        continue  # Skip self
                        
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((peer_ip, peer_port))
                    sock.send(f"SYNC REGISTER {username}:{password_hash}".encode())
                    response = sock.recv(1024).decode()
                    sock.close()
                    
                    logger.info(f"User sync to {peer_ip}:{peer_port}: {response}")
                except Exception as e:
                    logger.error(f"Failed to sync user to {peer_ip}:{peer_port}: {e}")
                    
        return success, message
    
    def login_user(self, username, password):
        """Login user and set current session"""
        success, message, session_id = self.auth.login(username, password)
        if success:
            self.user_session = session_id
            self.current_username = username
        return success, message
    
    def logout_user(self):
        """Logout current user"""
        if self.user_session:
            result, message = self.auth.logout(self.user_session)
            self.user_session = None
            self.current_username = None
            return result, message
        return False, "No active session"
    
    def is_authenticated(self):
        """Check if a user is currently authenticated"""
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