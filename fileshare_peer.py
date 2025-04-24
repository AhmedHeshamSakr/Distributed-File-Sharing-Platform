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
    
    def _handle_download(self, conn, data):
        """Handle file download request"""
        try:
            parts = data.split()
            if len(parts) < 2:
                conn.send(b"ERROR: Invalid download format")
                return
            
            if len(parts) == 3:  # With session
                _, file_id, session_id = parts
                # Verify session
                valid, username = self.auth.validate_session(session_id)
                if not valid:
                    conn.send(b"ERROR: Authentication required")
                    return
            else:
                conn.send(b"ERROR: Authentication required")
                return
            
            if file_id not in self.shared_files:
                conn.send(b"ERROR: File not found")
                return
                
            file_info = self.shared_files[file_id]
            file_path = file_info["path"]
            
            # Get actual file size rather than relying on stored metadata
            file_size = os.path.getsize(file_path)
            
            # Send file header with metadata - ensure proper encoding and separation
            header = f"FILE: {file_info['name']} {file_size}"
            conn.send(header.encode())
            
            # Wait for client acknowledgment with timeout
            conn.settimeout(10)
            try:
                response = conn.recv(1024).decode()
                if not response.startswith("OK"):
                    logger.warning(f"Client rejected download: {response}")
                    return
            except socket.timeout:
                logger.error("Timeout waiting for client acknowledgment")
                return
            
            # Send the file in chunks with robust error handling
            sent = 0
            with open(file_path, 'rb') as f:
                while sent < file_size:
                    # Read a chunk, respecting remaining bytes
                    remaining = file_size - sent
                    chunk_size = min(4096, remaining)
                    chunk = f.read(chunk_size)
                    
                    if not chunk:  # End of file
                        if sent < file_size:
                            logger.warning(f"File ended unexpectedly at {sent}/{file_size} bytes")
                        break
                    
                    # Try to send with timeout and retry logic
                    try:
                        conn.settimeout(30)  # Longer timeout for data transfer
                        conn.sendall(chunk)
                        sent += len(chunk)
                        
                        # Get acknowledgment periodically (but not too frequently)
                        if sent % (5*1024*1024) == 0 and sent < file_size:  # Every 5MB
                            conn.settimeout(10)
                            try:
                                ack = conn.recv(1024)
                                if not ack.startswith(b"ACK"):
                                    logger.warning(f"Unexpected acknowledgment: {ack}")
                            except socket.timeout:
                                logger.warning("Timeout waiting for acknowledgment, continuing anyway")
                    except socket.error as e:
                        logger.error(f"Socket error while sending file: {e}")
                        return
            
            logger.info(f"File {file_id} downloaded by {username}: {sent}/{file_size} bytes")
        
        except Exception as e:
            try:
                conn.send(f"ERROR: {str(e)}".encode())
            except:
                pass  # Connection might be closed already
            logger.error(f"Download error: {e}")

    def _handle_search(self, conn):
        """Handle search request for available files"""
        try:
            # Format: file_id:name:size:owner
            files = [f"{fid}:{info['name']}:{info['size']}:{info.get('owner', 'unknown')}" 
                     for fid, info in self.shared_files.items()]
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

    def _handle_upload(self, conn, data):
        """Handle file upload from another peer"""
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
            
            # Generate file ID and prepare destination path
            file_id = str(uuid.uuid4())
            dest_path = self.shared_dir / file_id
            
            # Acknowledge and prepare for upload
            conn.send(f"OK: {file_id}".encode())
            
            # Receive file
            received = 0
            last_progress = 0
            
            with open(dest_path, 'wb') as f:
                while received < file_size:
                    # Calculate appropriate chunk size
                    remaining = file_size - received
                    chunk_size = min(4096, remaining)
                    
                    # Receive chunk
                    chunk = conn.recv(chunk_size)
                    if not chunk:
                        break
                        
                    # Write chunk and update progress
                    f.write(chunk)
                    received += len(chunk)
                    
                    # Send progress updates
                    if received == file_size or received - last_progress >= 1024*1024:  # Every 1MB
                        progress = int(received * 100 / file_size)
                        conn.send(f"PROGRESS: {progress}".encode())
                        last_progress = received
            
            # Verify completeness
            if received < file_size:
                conn.send(b"ERROR: Incomplete upload")
                os.remove(dest_path)
                return
                
            # Store metadata
            self.shared_files[file_id] = {
                "name": file_name,
                "path": str(dest_path),
                "size": file_size,
                "owner": username
            }
            
            # Save metadata
            self._save_shared_files()
            
            # Send success response
            conn.send(b"SUCCESS: Upload complete")
            logger.info(f"File uploaded: {file_name} by {username}, ID: {file_id}")
            
        except Exception as e:
            try:
                conn.send(f"ERROR: {str(e)}".encode())
                # Clean up partial file
                if 'dest_path' in locals() and os.path.exists(dest_path):
                    os.remove(dest_path)
            except:
                pass
            logger.error(f"Upload error: {e}")

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
    
    # User authentication methods
    def register_user(self, username, password):
        """Register a new user"""
        return self.auth.register(username, password)
    
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