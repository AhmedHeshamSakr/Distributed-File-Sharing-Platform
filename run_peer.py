import argparse
import threading
import cmd
import sys
import getpass
from fileshare_peer import FileSharePeer
from fileshare_client import FileShareClient
import os

class FileShareCLI(cmd.Cmd):
    prompt = "ciphershare> "
    intro = "CipherShare: Secure P2P File Sharing System. Type 'help' for commands."
    
    def __init__(self, host, port, rendezvous_host, rendezvous_port):
        super().__init__()
        
        self.peer = FileSharePeer(host, port, rendezvous_host, rendezvous_port)
        self.client = FileShareClient(rendezvous_host, rendezvous_port)
        
        self.peer_thread = threading.Thread(target=self.peer.start)
        self.peer_thread.daemon = True
        self.peer_thread.start()
        
        self.secure_storage_initialized = False
    
    def do_init_secure_storage(self, arg):
        if self.secure_storage_initialized:
            print("Secure storage is already initialized")
            return
            
        print("Please enter a master password for secure credential storage:")
        master_password = getpass.getpass()
        
        if not master_password:
            print("Master password cannot be empty")
            return
            
        print("Confirm master password:")
        confirm_password = getpass.getpass()
        
        if master_password != confirm_password:
            print("Passwords do not match")
            return
            
        success = self.client.init_secure_storage(master_password)
        if success:
            self.secure_storage_initialized = True
            print("Secure storage initialized successfully")
        else:
            print("Failed to initialize secure storage")
    
    def update_prompt(self):
        if self.peer.is_authenticated():
            self.prompt = f"{self.peer.current_username}> "
        else:
            self.prompt = "ciphershare> "

    def do_login(self, arg):
        args = arg.split(maxsplit=1)
        if len(args) == 1:
            username = args[0]
            print(f"Enter password for {username}:")
            password = getpass.getpass()
        elif len(args) == 2:
            username, password = args
        else:
            print("Usage: login <username> [<password>]")
            return
            
        success, message = self.peer.login_user(username, password)
        
        if success:
            self.update_prompt()
            
            peers = self.client.get_peers()
            if peers:
                auth_success_count = 0
                for peer_ip, peer_port in peers:
                    try:
                        print(f"Authenticating with peer {peer_ip}:{peer_port}...")
                        client_success, client_message = self.client.login(peer_ip, peer_port, username, password)
                        if client_success:
                            auth_success_count += 1
                        else:
                            print(f"Warning: Authentication failed with peer {peer_ip}:{peer_port}: {client_message}")
                    except Exception as e:
                        print(f"Error connecting to peer {peer_ip}:{peer_port}: {e}")
                
                print(f"Successfully authenticated with {auth_success_count} out of {len(peers)} peers")
                
                if auth_success_count == 0:
                    print("Warning: Not authenticated with any remote peers. Downloads may fail.")
            else:
                print("No other peers found in the network.")
                
        print(message)

    def do_logout(self, arg):
        success, message = self.peer.logout_user()
        self.client.logout()
        self.update_prompt()
        print(message)

    def do_search(self, arg):
        if not self.client.is_authenticated():
            if self.peer.is_authenticated():
                peers = self.client.get_peers()
                for peer_ip, peer_port in peers:
                    self.client.login(peer_ip, peer_port, self.peer.current_username, "")
                    if self.client.is_authenticated():
                        break
            
            if not self.client.is_authenticated():
                print("Warning: Not authenticated with any peers. Search results may be limited.")
        
        files = self.client.search_files()
        
        if not files:
            print("No files found in the network.")
            return
            
        print("\nAvailable files:")
        print("-----------------------------------------------------")
        print(f"{'ID':<8} {'Size':<10} {'Peer':<21} {'Owner':<15} {'Access':<10} {'Name'}")
        print("-----------------------------------------------------")
        
        for i, (ip, port, file_id, name, size, owner, access_type) in enumerate(files, 1):
            size_str = self._format_size(size)
            print(f"{i:<8} {size_str:<10} {ip}:{port:<21} {owner:<15} {access_type:<10} {name}")

    def do_download(self, arg):
        if not self.peer.is_authenticated():
            print("You must be logged in to download files. Use 'login <username> <password>'")
            return
            
        args = arg.split()
        if not args:
            print("Please specify a file ID to download")
            return
                
        try:
            files = self.client.search_files()
            if not files:
                print("No files available to download")
                return
                    
            file_idx = int(args[0]) - 1
            if file_idx < 0 or file_idx >= len(files):
                print(f"Invalid file ID. Use 'search' to see available files")
                return
                    
            ip, port, file_id, name, size, owner, access_type = files[file_idx]
                
            destination = None
            if len(args) > 1:
                destination = args[1]
                
            print(f"Downloading '{name}' ({self._format_size(size)}) from {ip}:{port}...")
            
            success = self.client.download_file(ip, port, file_id, destination)
                
            if success:
                print("Download complete!")
            else:
                print("Download failed.")
            
        except ValueError:
            print("Invalid file ID. Please enter a number from the search results")
        except Exception as e:
            print(f"Error downloading file: {e}")

    def do_register(self, arg):
        args = arg.split(maxsplit=1)
        
        if len(args) == 1:
            username = args[0]
            print(f"Enter password for new user {username}:")
            password = getpass.getpass()
            print("Confirm password:")
            confirm_password = getpass.getpass()
            
            if password != confirm_password:
                print("Passwords do not match")
                return
        elif len(args) == 2:
            username, password = args
        else:
            print("Usage: register <username> [<password>]")
            return
            
        print(f"Registering user {username} across the network...")
        success, message = self.peer.register_user(username, password)
        
        if success:
            print("Registration successful! The account has been synchronized with other peers.")
        else:
            print(f"Registration failed: {message}")

    def do_whoami(self, arg):
        if self.peer.is_authenticated():
            print(f"Logged in as: {self.peer.current_username}")
        else:
            print("Not logged in")

    def do_share(self, arg):
        if not self.peer.is_authenticated():
            print("You must be logged in to share files. Use 'login <username> <password>'")
            return
                
        if not arg:
            print("Please specify a file path to share")
            return
                    
        file_id, message = self.peer.share_file(arg)
        if file_id:
            print(f"File shared successfully with ID: {file_id}")
        else:
            print(f"Failed to share file: {message}")

    def do_share_with(self, arg):
        if not self.peer.is_authenticated():
            print("You must be logged in to share files. Use 'login <username> <password>'")
            return
            
        args = arg.split(' ', 1)
        if len(args) != 2:
            print("Usage: share_with <filepath> <username1,username2,...>")
            return
            
        filepath, users_str = args
        allowed_users = [user.strip() for user in users_str.split(',')]
        
        file_id, message = self.peer.share_file_with_users(filepath, allowed_users)
        if file_id:
            print(f"File shared successfully with ID: {file_id}")
            print(f"Shared with users: {', '.join(allowed_users)}")
        else:
            print(f"Failed to share file: {message}")

    def do_help(self, arg):
        if arg:
            super().do_help(arg)
        else:
            print("\nCipherShare: Secure P2P File Sharing System Commands:")
            print("\nUser Management:")
            print("  register <user> [<pass>] - Register a new user account")
            print("  login <user> [<pass>]    - Login to your account")
            print("  logout                   - Logout from your account")
            print("  whoami                   - Show current user")
            print("  init_secure_storage      - Initialize secure credential storage")
            
            print("\nFile Operations:")
            print("  search                   - Search for files in the network")
            print("  share <filepath>         - Share a file with all users")
            print("  share_with <path> <users>- Share a file with specific users")
            print("  download <id> [dest]     - Download a file (id from search)")
            
            print("\nNetwork Operations:")
            print("  peers                    - Show active peers")
            print("  myfiles                  - Show your shared files")
            
            print("\nSystem:")
            print("  exit                     - Exit the program")
            print("\nFor more details on a command, type 'help command'")

            print("\nFile Operations:")
            print("  search                   - Search for files in the network")
            print("  share <filepath>         - Share a file with all users")
            print("  share_with <path> <users>- Share a file with specific users")
            print("  shared_with_me           - Show files shared with you")
            print("  download <id> [dest]     - Download a file (id from search)")
        
    def do_peers(self, arg):
        peers = self.client.get_peers()
        
        if not peers:
            print("No active peers found.")
            return
            
        print("\nActive peers:")
        print("------------------")
        for i, (ip, port) in enumerate(peers, 1):
            print(f"{i}. {ip}:{port}")
        print(f"\nTotal: {len(peers)} peers")
    
    def do_myfiles(self, arg):
        if not self.peer.shared_files:
            print("You are not sharing any files.")
            return
            
        print("\nMy shared files:")
        print("---------------------------------------------------------------------------------")
        print(f"{'ID':<8} {'Size':<10} {'Chunked':<10} {'Access':<15} {'Name'}")
        print("---------------------------------------------------------------------------------")
        
        for i, (file_id, info) in enumerate(self.peer.shared_files.items(), 1):
            size_str = self._format_size(info['size'])
            chunked = "Yes" if info.get('chunked', False) else "No"
            allowed_users = info.get('allowed_users', [])
            access = f"Restricted ({len(allowed_users)})" if allowed_users else "Public"
            
            print(f"{i:<8} {size_str:<10} {chunked:<10} {access:<15} {info['name']}")
            
            if allowed_users:
                users_list = ", ".join(allowed_users)
                print(f"  Allowed users: {users_list}")
    
    def do_exit(self, arg):
        print("Shutting down peer...")
        self.peer.running = False
        return True
    
    def _format_size(self, size_bytes):
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes/(1024*1024):.1f} MB"
        else:
            return f"{size_bytes/(1024*1024*1024):.1f} GB"

    def do_shared_with_me(self, arg):
        if not self.peer.is_authenticated():
            print("You must be logged in to see files shared with you.")
            return
            
        shared_files = self.peer.update_shared_with_me()
        
        if not shared_files:
            print("No files have been shared with you.")
            return
            
        print("\nFiles shared with me:")
        print("---------------------------------------------------------------------------------")
        print(f"{'ID':<8} {'Size':<10} {'Owner':<15} {'Peer':<21} {'Name'}")
        print("---------------------------------------------------------------------------------")
        
        for i, (file_id, info) in enumerate(shared_files.items(), 1):
            size_str = self._format_size(info['size'])
            owner = info.get('owner', 'unknown')
            peer = f"{info['peer_ip']}:{info['peer_port']}"
            
            print(f"{i:<8} {size_str:<10} {owner:<15} {peer:<21} {info['name']}")

def main():
    parser = argparse.ArgumentParser(description="CipherShare P2P File Sharing")
    parser.add_argument("--host", default="127.0.0.1", help="Host IP for this peer")
    parser.add_argument("--port", type=int, default=0, help="Port for this peer (0 for random)")
    parser.add_argument("--rendezvous-host", default="127.0.0.1", help="Rendezvous server IP")
    parser.add_argument("--rendezvous-port", type=int, default=5555, help="Rendezvous server port")
    
    args = parser.parse_args()
    
    if args.port == 0:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', 0))
        args.port = s.getsockname()[1]
        s.close()
    
    try:
        cli = FileShareCLI(args.host, args.port, args.rendezvous_host, args.rendezvous_port)
        cli.cmdloop()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

    