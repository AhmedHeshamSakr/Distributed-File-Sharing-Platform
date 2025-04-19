

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
    
    def download_file(self, peer_ip, peer_port, file_id, save_path=None):
        """Download a file from a specific peer"""
        sock = None
        temp_path = None
        
        try:
            # Connect to peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)  # Longer timeout for large files
            sock.connect((peer_ip, peer_port))
            
            # Send download request
            sock.send(f"DOWNLOAD {file_id}".encode())
            
            # Get file metadata
            sock.settimeout(10)  # Shorter timeout for metadata
            response = sock.recv(1024).decode()
            if response.startswith("ERROR"):
                logger.error(f"Download error: {response}")
                return False
                
            if not response.startswith("FILE:"):
                logger.error(f"Invalid response: {response}")
                return False
            
            # Parse file metadata safely
            try:
                _, metadata = response.split(':', 1)
                parts = metadata.strip().split(' ', 2)
                if len(parts) != 3:
                    logger.error(f"Invalid file metadata format: {metadata}")
                    return False
                    
                file_name, file_size_str, file_hash = parts
                file_size = int(file_size_str)
                
                # Log the hash we're expecting
                logger.debug(f"Expected file hash: {file_hash}")
                
                if file_size <= 0:
                    logger.error(f"Invalid file size: {file_size}")
                    return False
            except (ValueError, IndexError) as e:
                logger.error(f"Error parsing metadata: {e}, raw: {response}")
                return False
            
            # Determine save path
            if save_path is None:
                save_path = self.download_dir / file_name
            
            # Use a temporary file during download
            temp_path = f"{save_path}.part"
            
            # Acknowledge and start download
            sock.send(b"OK: Ready to receive")
            
            # Receive file with proper timeouts
            received = 0
            start_time = time.time()
            last_progress_report = 0
            
            with open(temp_path, 'wb') as f:
                sock.settimeout(30)  # Longer timeout for data transfer
                
                while received < file_size:
                    try:
                        # Calculate appropriate chunk size
                        remaining = file_size - received
                        expected_chunk = min(4096, remaining)
                        
                        # Receive chunk with timeout
                        chunk = sock.recv(expected_chunk)
                        if not chunk:  # Connection closed
                            break
                        
                        # Write chunk and update stats
                        f.write(chunk)
                        received += len(chunk)
                        
                        # Send acknowledgment periodically
                        if received % (5*1024*1024) == 0 and received < file_size:  # Every 5MB
                            sock.send(b"ACK")
                        
                        # Print progress (not too frequently)
                        now = time.time()
                        if now - last_progress_report >= 1 or received == file_size:
                            elapsed = now - start_time
                            if elapsed > 0:  # Avoid division by zero
                                progress = min(100, int(received * 100 / file_size))
                                speed = received / elapsed / 1024
                                logger.info(f"Download progress: {progress}% ({speed:.1f} KB/s)")
                            last_progress_report = now
                    
                    except socket.timeout:
                        logger.warning("Socket timeout during download, retrying...")
                        continue
                    except socket.error as e:
                        logger.error(f"Socket error: {e}")
                        return False
            
            # Close socket after download
            try:
                sock.close()
                sock = None
            except:
                pass
            
            # Verify download completeness
            if received < file_size:
                logger.error(f"Incomplete download: got {received}/{file_size} bytes")
                return False
            
            # Verify file hash
            calculated_hash = self._calculate_file_hash(temp_path)
            logger.debug(f"Calculated hash: {calculated_hash}")
            
            if calculated_hash != file_hash:
                logger.error(f"File hash verification failed. Expected: {file_hash}, Got: {calculated_hash}")
                # For debugging purposes, we could save the failed file with a different extension
                debug_path = f"{save_path}.failed"
                try:
                    os.replace(temp_path, debug_path)
                    logger.info(f"Saved problematic file to {debug_path} for debugging")
                    temp_path = None
                except:
                    pass
                return False
            
            # Rename temp file to final filename
            os.replace(temp_path, save_path)
            temp_path = None
            
            logger.info(f"Download successful: {file_name} saved to {save_path}")
            return True
        
        except Exception as e:
            logger.error(f"Download error: {e}")
            return False
        
        finally:
            # Clean up resources
            if sock:
                try:
                    sock.close()
                except:
                    pass
            
            # Remove temporary file if exists
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass

    def _calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        try:
            # Ensure binary mode for consistent hashing
            with open(filepath, 'rb') as f:
                # Read in reasonably sized chunks
                for block in iter(lambda: f.read(4096), b''):
                    sha256.update(block)
            hash_result = sha256.hexdigest()
            logger.debug(f"Calculated hash for {filepath}: {hash_result[:8]}...")
            return hash_result
        except Exception as e:
            logger.error(f"Error calculating file hash for {filepath}: {e}")
            # Return a dummy hash that will never match
            return "error-calculating-hash"