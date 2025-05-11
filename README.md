# CipherShare: Secure Distributed File Sharing Platform

CipherShare is a peer-to-peer (P2P) file sharing application that prioritizes security and user control over their credentials. The platform enables users to securely share files in a distributed network environment, ensuring confidentiality, integrity, and authenticated access.

## Features

- **Secure User Authentication**: Strong password-based authentication using Argon2id hashing
- **End-to-End Encryption**: Files are encrypted before sharing using AES-256-CBC
- **Distributed P2P Network**: Users can connect directly to share files without central servers
- **Access Control**: Share files with all users or restrict access to specific users
- **File Integrity Verification**: SHA-256 hashing ensures files aren't tampered with
- **Chunked File Transfer**: Large files are split into manageable chunks for efficient transfer
- **Multiple Interfaces**: Both command-line and graphical user interfaces
- **Secure Credential Storage**: Optional encrypted local storage for credentials

## Architecture

The system consists of the following components:

1. **Rendezvous Server**: Helps peers discover each other in the network
2. **Peer Nodes**: Each user runs a peer that can both share and download files
3. **Client Interface**: Connects to peers to perform file operations
4. **Authentication System**: Manages user registration, login, and sessions
5. **Cryptographic Utilities**: Handles encryption, decryption, and hashing

## Project Structure

```
Distributed-File-Sharing-Platform/
    ├── rendezvous_server.py   # Central server for peer discovery
    ├── fileshare_peer.py      # Peer node implementation
    ├── fileshare_client.py    # Client for interacting with peers
    ├── user_auth.py           # User authentication system
    ├── crypto_utils.py        # Cryptographic utilities
    ├── run_server.py          # Script to run the rendezvous server
    ├── run_peer.py            # Script to run a peer with CLI
    ├── ciphershare_gui.py     # GUI implementation (optional)
    └── README.md              # Documentation
```

## Setup

1. First start the rendezvous server:
   ```
   python run_server.py --port 5555
   ```

2. Then start one or more peers:
   ```
   python run_peer.py --rendezvous-host 127.0.0.1 --rendezvous-port 5555 
   ```

3. For the GUI interface (if implemented):
   ```
   python ciphershare_gui.py --rendezvous-host 127.0.0.1 --rendezvous-port 5555
   ```

## Using the Command Line Interface

From the peer command prompt, you can:
- Register a new user: `register <username> <password>`
- Login to your account: `login <username> <password>`
- Share files: `share /path/to/file.txt`
- Share with specific users: `share_with /path/to/file.txt user1,user2,user3`
- Search for files: `search`
- Download files: `download 1` (where 1 is the file ID from search results)
- View active peers: `peers`
- View your shared files: `myfiles`
- View files shared with you: `shared_with_me`
- Initialize secure storage: `init_secure_storage`
- Logout from your account: `logout`
- Show current user: `whoami`
- Exit the program: `exit`

## Security Features

### Password Hashing
Passwords are hashed using Argon2id with appropriate time and memory parameters, combined with unique salts for each user.

### File Encryption
Files are encrypted using AES-256-CBC with proper padding before being shared on the network.

### Secure Sessions
Session tokens are generated using UUIDs and are validated for each operation.

### Access Control
Files can be shared publicly (accessible to all authenticated users) or restricted to specific users.

## Network Testing

For local testing, start multiple peers with different port numbers:
```
python run_peer.py --port 6001 --rendezvous-host 127.0.0.1
python run_peer.py --port 6002 --rendezvous-host 127.0.0.1
```

## Dependencies

- cryptography
- customtkinter (for GUI)
- Pillow (for GUI)

## Implementation Details

### Cryptographic Algorithms Used
- Symmetric Encryption: AES-256-CBC
- Password Hashing: Argon2id
- File Integrity: SHA-256
- Key Derivation: PBKDF2HMAC

### Key Components

1. **FileSharePeer**: Handles sharing files, responding to download requests, and managing user authentication
2. **FileShareClient**: Manages connections to peers, file searching, and downloading
3. **UserAuth**: Provides user registration, login, and session management
4. **CryptoUtils**: Implements cryptographic operations
5. **RendezvousServer**: Maintains a list of active peers and facilitates peer discovery