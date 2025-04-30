
# run_peer.py - Entry point for running a peer with CLI
import argparse
import threading
import cmd
import sys
from fileshare_peer import FileSharePeer
from fileshare_client import FileShareClient

import os

class FileShareCLI(cmd.Cmd):
    prompt = "p2p> "
    intro = "P2P File Sharing System. Type 'help' for commands."
    
    def __init__(self, host, port, rendezvous_host, rendezvous_port):
        super().__init__()
        
        # Initialize peer and client
        self.peer = FileSharePeer(host, port, rendezvous_host, rendezvous_port)
        self.client = FileShareClient(rendezvous_host, rendezvous_port)
        
        # Start peer server in a separate thread
        self.peer_thread = threading.Thread(target=self.peer.start)
        self.peer_thread.daemon = True
        self.peer_thread.start()
    
    def update_prompt(self):
        """Update the command prompt to reflect the current login state"""
        if self.peer.is_authenticated():
            self.prompt = f"{self.peer.current_username}> "
        else:
            self.prompt = "p2p> "

    def do_login(self, arg):
        """Login to your account (usage: login <username> <password>)"""
        args = arg.split()
        if len(args) != 2:
            print("Usage: login <username> <password>")
            return
            
        username, password = args
        success, message = self.peer.login_user(username, password)
        
        # If local login succeeded, authenticate with all peers
        if success:
            # Update the prompt immediately
            self.update_prompt()
            
            # Get all available peers
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

    # Update do_logout to reset the prompt
    def do_logout(self, arg):
        """Logout from your account"""
        success, message = self.peer.logout_user()
        # Also logout the client
        self.client.logout()
        # Reset the prompt
        self.update_prompt()
        print(message)

    # Modify do_search to better handle authentication
    def do_search(self, arg):
        """Search for available files in the network"""
        if not self.client.is_authenticated():
            # Try to automatically authenticate the client with the current peer session
            if self.peer.is_authenticated():
                peers = self.client.get_peers()
                for peer_ip, peer_port in peers:
                    self.client.login(peer_ip, peer_port, self.peer.current_username, "")  # Password won't be used here
                    # Just try to authenticate with at least one peer
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
        print(f"{'ID':<8} {'Size':<10} {'Peer':<21} {'Name'}")
        print("-----------------------------------------------------")
        
        for i, (ip, port, file_id, name, size) in enumerate(files, 1):
            size_str = self._format_size(size)
            print(f"{i:<8} {size_str:<10} {ip}:{port:<21} {name}")

    # Update do_download to handle authentication better
    def do_download(self, arg):
        """Download a file (usage: download <id> [destination])"""
        # Check authentication
        if not self.peer.is_authenticated():
            print("You must be logged in to download files. Use 'login <username> <password>'")
            return
            
        args = arg.split()
        if not args:
            print("Please specify a file ID to download")
            return
                
        try:
            # First search to populate the file list
            files = self.client.search_files()
            if not files:
                print("No files available to download")
                return
                    
            # Get the file by ID
            file_idx = int(args[0]) - 1
            if file_idx < 0 or file_idx >= len(files):
                print(f"Invalid file ID. Use 'search' to see available files")
                return
                    
            # Extract file info
            ip, port, file_id, name, size = files[file_idx]
                
            # Determine destination path
            destination = None
            if len(args) > 1:
                destination = args[1]
                
            print(f"Downloading '{name}' ({self._format_size(size)}) from {ip}:{port}...")
            
            # Use existing session instead of re-logging in
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
        """Register a new user (usage: register <username> <password>)"""
        args = arg.split()
        if len(args) != 2:
            print("Usage: register <username> <password>")
            return
            
        username, password = args
        print(f"Registering user {username} across the network...")
        success, message = self.peer.register_user(username, password)
        
        if success:
            print("Registration successful! The account has been synchronized with other peers.")
        else:
            print(f"Registration failed: {message}")

    def do_whoami(self, arg):
            """Show current logged in user"""
            if self.peer.is_authenticated():
                print(f"Logged in as: {self.peer.current_username}")
            else:
                print("Not logged in")

        # 2. Update do_share to check for authentication:
    def do_share(self, arg):
            """Share a local file (usage: share <filepath>)"""
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

    def do_help(self, arg):
        """Show help information"""
        if arg:
            # Show help for specific command
            super().do_help(arg)
        else:
            # Show general help
            print("\nP2P File Sharing System Commands:")
            print("  register <user> <pass> - Register a new user account")
            print("  login <user> <pass>    - Login to your account")
            print("  logout                 - Logout from your account")
            print("  whoami                 - Show current user")
            print("  search                 - Search for files in the network")
            print("  share <filepath>       - Share a file with the network")
            print("  download <id> [dest]   - Download a file (id from search)")
            print("  peers                  - Show active peers")
            print("  myfiles                - Show your shared files")
            print("  exit                   - Exit the program")
            print("\nFor more details on a command, type 'help command'")
        
    def do_peers(self, arg):
        """Show the list of active peers in the network"""
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
        """Show the files you are sharing"""
        if not self.peer.shared_files:
            print("You are not sharing any files.")
            return
            
        print("\nMy shared files:")
        print("-----------------------------------------------------")
        print(f"{'ID':<36} {'Size':<10} {'Name'}")
        print("-----------------------------------------------------")
        
        for file_id, info in self.peer.shared_files.items():
            size_str = self._format_size(info['size'])
            print(f"{file_id:<36} {size_str:<10} {info['name']}")
    
    def do_exit(self, arg):
        """Exit the program"""
        print("Shutting down peer...")
        self.peer.running = False
        return True
    
    def _format_size(self, size_bytes):
        """Format file size in human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes/(1024*1024):.1f} MB"
        else:
            return f"{size_bytes/(1024*1024*1024):.1f} GB"


def main():
    parser = argparse.ArgumentParser(description="P2P File Sharing Peer")
    parser.add_argument("--host", default="127.0.0.1", help="Host IP for this peer")
    parser.add_argument("--port", type=int, default=0, help="Port for this peer (0 for random)")
    parser.add_argument("--rendezvous-host", default="127.0.0.1", help="Rendezvous server IP")
    parser.add_argument("--rendezvous-port", type=int, default=5555, help="Rendezvous server port")
    
    args = parser.parse_args()
    
    # Use random port if not specified
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