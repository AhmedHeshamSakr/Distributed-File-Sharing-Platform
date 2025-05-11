import hashlib
import json
import os
import time
import uuid
import logging
import base64
from pathlib import Path
import crypto_utils

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('UserAuth')

class UserAuth:
    def __init__(self):
        self.users_dir = Path("users")
        self.users_dir.mkdir(exist_ok=True)
        self.users_file = self.users_dir / "users.json"
        self.sessions = {}
        self.session_duration = 24 * 60 * 60
        self._load_users()
    
    def _hash_password(self, password):
        hash_bytes, salt = crypto_utils.hash_password_argon2(password)
        return {
            "hash": crypto_utils.encode_bytes(hash_bytes),
            "salt": crypto_utils.encode_bytes(salt)
        }
    
    def _verify_password(self, password, hash_data):
        stored_hash = crypto_utils.decode_bytes(hash_data["hash"])
        salt = crypto_utils.decode_bytes(hash_data["salt"])
        
        return crypto_utils.verify_password_argon2(password, stored_hash, salt)
    
    def _load_users(self):
        if self.users_file.exists():
            try:
                with open(self.users_file, 'r') as f:
                    self.users = json.load(f)
                logger.info(f"Loaded {len(self.users)} users from database")
            except Exception as e:
                logger.error(f"Failed to load users: {e}")
                self.users = {}
        else:
            self.users = {}
    
    def _save_users(self):
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f)
            logger.info(f"Saved {len(self.users)} users to database")
        except Exception as e:
            logger.error(f"Failed to save users: {e}")
    
    def register(self, username, password):
        if username in self.users:
            logger.warning(f"Username already exists: {username}")
            return False, "Username already exists"
        
        password_data = self._hash_password(password)
        
        self.users[username] = {
            "password_hash": password_data["hash"],
            "password_salt": password_data["salt"],
            "created_at": time.time()
        }
        
        self._save_users()
        logger.info(f"User registered: {username}")
        return True, "Registration successful"
    
    def add_remote_user(self, username, password_hash_data):
        if username in self.users:
            existing_user = self.users[username]
            if existing_user.get("is_remote", False):
                try:
                    hash_data = json.loads(password_hash_data)
                    self.users[username].update(hash_data)
                    self.users[username]["updated_at"] = time.time()
                    self._save_users()
                    logger.info(f"Updated remote user: {username}")
                    return True, "User updated"
                except Exception as e:
                    logger.error(f"Error updating remote user: {e}")
                    return False, str(e)
            return False, "User already exists locally"
        
        try:
            hash_data = json.loads(password_hash_data)
            self.users[username] = hash_data
            self.users[username]["created_at"] = time.time()
            self.users[username]["is_remote"] = True
            self._save_users()
            logger.info(f"Added remote user: {username}")
            return True, "User added"
        except Exception as e:
            logger.error(f"Error adding remote user: {e}")
            return False, str(e)
    
    def get_user_data(self, username):
        if username in self.users:
            user_data = dict(self.users[username])
            user_data["sync_time"] = time.time()
            return user_data
        return None
    
    def login(self, username, password):
        if username not in self.users:
            logger.warning(f"Login failed: User {username} not found")
            return False, "Invalid username or password", None
        
        user_data = self.users[username]
        
        if "password_hash" not in user_data or "password_salt" not in user_data:
            logger.error(f"User {username} has invalid password data")
            return False, "Account data is corrupted", None
        
        password_data = {
            "hash": user_data["password_hash"],
            "salt": user_data["password_salt"]
        }
        
        if not self._verify_password(password, password_data):
            logger.warning(f"Login failed: Incorrect password for {username}")
            return False, "Invalid username or password", None
        
        session_id = str(uuid.uuid4())
        expiry = time.time() + self.session_duration
        
        salt = crypto_utils.decode_bytes(user_data["password_salt"])
        encryption_key = crypto_utils.derive_key_from_password(password, salt)
        
        self.sessions[session_id] = {
            "username": username,
            "expires": expiry,
            "encryption_key": crypto_utils.encode_bytes(encryption_key)
        }
        
        logger.info(f"User logged in: {username}")
        return True, "Login successful", session_id
    
    def validate_session(self, session_id):
        if session_id not in self.sessions:
            return False, None
        
        session = self.sessions[session_id]
        if time.time() > session["expires"]:
            del self.sessions[session_id]
            return False, None
        
        return True, session["username"]
    
    def get_user_encryption_key(self, session_id):
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        if time.time() > session["expires"]:
            del self.sessions[session_id]
            return None
        
        return crypto_utils.decode_bytes(session["encryption_key"])
    
    def logout(self, session_id):
        if session_id in self.sessions:
            username = self.sessions[session_id]["username"]
            del self.sessions[session_id]
            logger.info(f"User logged out: {username}")
            return True, "Logout successful"
        return False, "Session not found"
    
    def cleanup_sessions(self):
        current_time = time.time()
        expired = [sid for sid, data in self.sessions.items() if data["expires"] < current_time]
        
        for sid in expired:
            del self.sessions[sid]
        
        if expired:
            logger.debug(f"Removed {len(expired)} expired sessions")
    
    def verify_password(self, username, password):
        if username not in self.users:
            return False
        
        user_data = self.users[username]
        password_data = {
            "hash": user_data["password_hash"],
            "salt": user_data["password_salt"]
        }
        
        return self._verify_password(password, password_data)