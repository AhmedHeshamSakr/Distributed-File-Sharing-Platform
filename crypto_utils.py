from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import os
import base64
import json
import logging
import secrets

logger = logging.getLogger('CryptoUtils')

class KeyManager:
    def __init__(self, key_file_path="encryption_key.dat"):
        self.key_file_path = key_file_path
        self.system_key = self._load_or_create_system_key()
        self.file_keys = {}
        logger.info(f"Key manager initialized with key length: {len(self.system_key)} bytes")
    
    def _load_or_create_system_key(self):
        try:
            with open(self.key_file_path, 'rb') as f:
                key = f.read()
                if len(key) != 32:
                    logger.warning(f"Invalid key length ({len(key)}), generating new key")
                    raise ValueError("Invalid key length")
                logger.info("Loaded existing encryption key")
                return key
        except (FileNotFoundError, ValueError):
            key = os.urandom(32)
            logger.info("Generated new encryption key")
            
            with open(self.key_file_path, 'wb') as f:
                f.write(key)
            return key
            
    def get_encryption_key(self, file_id=None):
        if file_id is None or file_id not in self.file_keys:
            return self.system_key
        return self.file_keys[file_id]
    
    def generate_file_key(self, file_id):
        key = os.urandom(32)
        self.file_keys[file_id] = key
        return key
    
    def store_file_key(self, file_id, key):
        self.file_keys[file_id] = key
        return True

def encrypt_data(data, key):
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_data(encrypted_data, key):
    try:
        if len(encrypted_data) < 32:
            raise ValueError(f"Encrypted data too short ({len(encrypted_data)} bytes), minimum is 32 bytes")
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        remainder = len(ciphertext) % 16
        if remainder != 0:
            padding_length = 16 - remainder
            ciphertext += bytes([0] * padding_length)
            logger.warning(f"Padded ciphertext with {padding_length} zeros to make length {len(ciphertext)}")
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        try:
            data = unpadder.update(padded_data) + unpadder.finalize()
            return data
        except ValueError as e:
            logger.error(f"Padding error: {e}")
            return padded_data
        
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise

def hash_password_argon2(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    
    try:
        argon2 = Argon2id(
            salt=salt,
            length=32,
            t_cost=4,
            m_cost=65536,
            p=4,
            backend=default_backend()
        )
    except TypeError:
        try:
            argon2 = Argon2id(
                salt=salt,
                length=32,
                iterations=4,
                memory_cost=65536,
                parallelism=4,
                backend=default_backend()
            )
        except TypeError:
            logger.warning("Argon2id implementation not working properly, falling back to PBKDF2")
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            return kdf.derive(password.encode('utf-8')), salt
    
    hash_bytes = argon2.derive(password.encode('utf-8'))
    return hash_bytes, salt

def verify_password_argon2(password, hash_bytes, salt):
    try:
        argon2 = Argon2id(
            salt=salt,
            length=len(hash_bytes),
            t_cost=4,
            m_cost=65536,
            p=4,
            backend=default_backend()
        )
    except TypeError:
        try:
            argon2 = Argon2id(
                salt=salt,
                length=len(hash_bytes),
                iterations=4,
                memory_cost=65536,
                parallelism=4,
                backend=default_backend()
            )
        except TypeError:
            logger.warning("Argon2id implementation not working properly, falling back to PBKDF2")
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=len(hash_bytes),
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            check_hash = kdf.derive(password.encode('utf-8'))
            return secrets.compare_digest(check_hash, hash_bytes)
    
    try:
        check_hash = argon2.derive(password.encode('utf-8'))
        return secrets.compare_digest(check_hash, hash_bytes)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def derive_key_from_password(password, salt, length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    key = kdf.derive(password.encode('utf-8'))
    return key

def compute_file_hash(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def verify_file_hash(data, expected_hash):
    actual_hash = compute_file_hash(data)
    return secrets.compare_digest(actual_hash, expected_hash)

def encode_bytes(data):
    return base64.b64encode(data).decode('utf-8')

def decode_bytes(data_str):
    return base64.b64decode(data_str.encode('utf-8'))

class EncryptedStorage:
    def __init__(self, master_password, storage_file="secure_storage.dat"):
        self.storage_file = storage_file
        self.master_salt = None
        self.master_key = None
        self._initialize_master_key(master_password)
        self.data = self._load_data()
    
    def _initialize_master_key(self, master_password):
        salt_file = self.storage_file + ".salt"
        
        if os.path.exists(salt_file):
            with open(salt_file, 'rb') as f:
                self.master_salt = f.read()
        else:
            self.master_salt = secrets.token_bytes(16)
            with open(salt_file, 'wb') as f:
                f.write(self.master_salt)
        
        self.master_key = derive_key_from_password(master_password, self.master_salt)
    
    def _load_data(self):
        if not os.path.exists(self.storage_file):
            return {}
        
        try:
            with open(self.storage_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = decrypt_data(encrypted_data, self.master_key)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            logger.error(f"Failed to load encrypted storage: {e}")
            return {}
    
    def _save_data(self):
        try:
            data_json = json.dumps(self.data).encode('utf-8')
            encrypted_data = encrypt_data(data_json, self.master_key)
            
            with open(self.storage_file, 'wb') as f:
                f.write(encrypted_data)
                
            return True
        except Exception as e:
            logger.error(f"Failed to save encrypted storage: {e}")
            return False
    
    def store(self, key, value):
        self.data[key] = value
        return self._save_data()
    
    def retrieve(self, key):
        return self.data.get(key)
    
    def delete(self, key):
        if key in self.data:
            del self.data[key]
            return self._save_data()
        return True
