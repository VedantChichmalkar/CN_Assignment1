import argparse
import client
import server

def main():
    """
    Main entry point for running the DNS client or server.
    """
    parser = argparse.ArgumentParser(description="Custom DNS Resolver Project")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # Subparser for the server
    server_parser = subparsers.add_parser("server", help="Run the DNS server")
    server_parser.add_argument("--host", default="127.0.0.1", help="Host to run the server on")
    server_parser.add_argument("--port", type=int, default=5300, help="Port to listen on")

    # Subparser for the client
    client_parser = subparsers.add_parser("client", help="Run the DNS client")
    client_parser.add_argument("--pcap_file", required=True, help="The pcap file to process")
    client_parser.add_argument("--server_ip", default="127.0.0.1", help="The IP address of the server")
    client_parser.add_argument("--server_port", type=int, default=5300, help="The port of the server")

    args = parser.parse_args()

    if args.command == "server":
        server.start_server(args.host, args.port)
    elif args.command == "client":
        client.start_client(args.pcap_file, args.server_ip, args.server_port)

if __name__ == "__main__":
    main()
