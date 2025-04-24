# user_auth.py
import hashlib
import json
import os
import time
import uuid
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('UserAuth')

class UserAuth:
    def __init__(self):
        self.users_dir = Path("users")
        self.users_dir.mkdir(exist_ok=True)
        self.users_file = self.users_dir / "users.json"
        self.sessions = {}  # {session_id: {"username": username, "expires": timestamp}}
        self.session_duration = 24 * 60 * 60  # 24 hours in seconds
        self._load_users()


    def verify_password(self, username, password):
        """Verify a username and password without creating a session"""
        if username not in self.users:
            return False
        
        stored_hash = self.users[username]["password_hash"]
        input_hash = self._hash_password(password)
        return input_hash == stored_hash
    
    def _load_users(self):
        """Load user data from file"""
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
        """Save user data to file"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f)
            logger.info(f"Saved {len(self.users)} users to database")
        except Exception as e:
            logger.error(f"Failed to save users: {e}")
    
    def _hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register(self, username, password):
        """Register a new user"""
        if username in self.users:
            logger.warning(f"Username already exists: {username}")
            return False, "Username already exists"
        
        hashed_password = self._hash_password(password)
        self.users[username] = {
            "password_hash": hashed_password,
            "created_at": time.time()
        }
        self._save_users()
        logger.info(f"User registered: {username}")
        return True, "Registration successful"
    
    def login(self, username, password):
        """Login user and return session ID"""
        if username not in self.users:
            logger.warning(f"Login failed: User {username} not found")
            return False, "Invalid username or password", None
        
        stored_hash = self.users[username]["password_hash"]
        input_hash = self._hash_password(password)
        
        if input_hash != stored_hash:
            logger.warning(f"Login failed: Incorrect password for {username}")
            return False, "Invalid username or password", None
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        expiry = time.time() + self.session_duration
        
        self.sessions[session_id] = {
            "username": username,
            "expires": expiry
        }
        
        logger.info(f"User logged in: {username}")
        return True, "Login successful", session_id
    
    def validate_session(self, session_id):
        """Validate if a session is active and return username"""
        if session_id not in self.sessions:
            return False, None
        
        session = self.sessions[session_id]
        if time.time() > session["expires"]:
            # Session expired
            del self.sessions[session_id]
            return False, None
        
        return True, session["username"]
    
    def logout(self, session_id):
        """Logout user by removing session"""
        if session_id in self.sessions:
            username = self.sessions[session_id]["username"]
            del self.sessions[session_id]
            logger.info(f"User logged out: {username}")
            return True, "Logout successful"
        return False, "Session not found"
    
    def cleanup_sessions(self):
        """Remove expired sessions"""
        current_time = time.time()
        expired = [sid for sid, data in self.sessions.items() if data["expires"] < current_time]
        
        for sid in expired:
            del self.sessions[sid]
        
        if expired:
            logger.debug(f"Removed {len(expired)} expired sessions")