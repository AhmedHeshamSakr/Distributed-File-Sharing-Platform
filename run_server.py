
# run_server.py - Entry point for running rendezvous server
import argparse
from rendezvous_server import RendezvousServer

def main():
    parser = argparse.ArgumentParser(description="P2P File Sharing Rendezvous Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host IP to bind to")
    parser.add_argument("--port", type=int, default=5555, help="Port to listen on")
    
    args = parser.parse_args()
    
    server = RendezvousServer(host=args.host, port=args.port)
    server.start()

if __name__ == "__main__":
    main()

