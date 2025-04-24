# Distributed-File-Sharing-Platform


### Distributed-File-Sharing-Platform/
    ├── rendezvous_server.py
    ├── fileshare_peer.py
    ├── fileshare_client.py
    ├── run_server.py
    └── run_peer.py

P2P File Sharing System
-----------------------

This is a simple peer-to-peer file sharing system with a rendezvous server for peer discovery.

### Components:
1. Rendezvous Server: Coordinates peer discovery
2. File Share Peer: Shares and hosts files
3. Client: Searches for and downloads files

### Setup:

1. First start the rendezvous server:
   ```
   python run_server.py --port 5555
   ```

2. Then start one or more peers:
   ```
   python run_peer.py --rendezvous-host 127.0.0.1 --rendezvous-port 5555 
   ```

3. From the peer command prompt, you can:
   - Share files: `share /path/to/file.txt`
   - Search for files: `search`
   - Download files: `download 1` (where 1 is the file ID from search results)
   - View active peers: `peers`
   - View your shared files: `myfiles`
   - Register a new user: `register <username> <password>`
   - Login to your account: `login <username> <password>`
   - Logout from your account: `logout`
   - Show current user: `whoami`
   - Exit the program: `exit`

### Network Testing:
For local testing, start multiple peers with different port numbers:
```
python run_peer.py --port 6001 --rendezvous-host 127.0.0.1
python run_peer.py --port 6002 --rendezvous-host 127.0.0.1
```
