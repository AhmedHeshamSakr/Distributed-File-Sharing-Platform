# crypto_utils.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import logging

logger = logging.getLogger('CryptoUtils')

class KeyManager:
    def __init__(self, key_file_path="encryption_key.dat"):
        self.key_file_path = key_file_path
        self.system_key = self._load_or_create_system_key()
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
            # Generate a new key if file doesn't exist or key is invalid
            key = os.urandom(32)  # 32 bytes = 256 bits for AES-256
            logger.info("Generated new encryption key")
            
            # Save the new key
            with open(self.key_file_path, 'wb') as f:
                f.write(key)
            return key
            
    def get_encryption_key(self, file_id=None):
        """Get encryption key for a file. For Phase 3, we use a single system key for all files."""
        return self.system_key

def encrypt_data(data, key):
    """
    Encrypt data using AES-256 in CBC mode with proper padding.
    
    Args:
        data (bytes): The data to encrypt
        key (bytes): 32-byte encryption key
        
    Returns:
        bytes: IV (16 bytes) + encrypted data
    """
    # Generate a random IV
    iv = os.urandom(16)
    
    # Create a padder to ensure data length is a multiple of block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Create the cipher using AES algorithm in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Log some debugging info
    logger.debug(f"Original data length: {len(data)}, Padded: {len(padded_data)}, Encrypted: {len(encrypted_data)}")
    
    # Return IV + encrypted data
    result = iv + encrypted_data
    return result

def decrypt_data(encrypted_data, key):
    """
    Decrypt data encrypted with AES-256 in CBC mode.
    
    Args:
        encrypted_data (bytes): IV (16 bytes) + encrypted data
        key (bytes): 32-byte encryption key
        
    Returns:
        bytes: Decrypted data
    """
    # Validate minimum length (IV + at least one block)
    if len(encrypted_data) < 32:
        raise ValueError(f"Encrypted data too short ({len(encrypted_data)} bytes), minimum is 32 bytes")
    
    # Extract the IV (first 16 bytes)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Verify block size
    remainder = len(ciphertext) % 16
    if remainder != 0:
        raise ValueError(f"Ciphertext length ({len(ciphertext)}) is not a multiple of block size (16), remainder: {remainder}")
    
    # Create the cipher for decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the padded data
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data

def compute_file_hash(data):
    """Compute SHA-256 hash of file data."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def verify_file_hash(data, expected_hash):
    """Verify that file data matches expected hash."""
    actual_hash = compute_file_hash(data)
    return actual_hash == expected_hash

def encode_bytes(data):
    """Convert binary data to a base64 string for storage"""
    return base64.b64encode(data).decode('utf-8')

def decode_bytes(data_str):
    """Convert a base64 string back to binary data"""
    return base64.b64decode(data_str.encode('utf-8'))