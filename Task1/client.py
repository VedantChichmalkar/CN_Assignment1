import socket
import argparse
from scapy.all import *
from datetime import datetime

def create_custom_header(seq_id):
    """Creates a custom header with the format HHMMSSID."""
    now = datetime.now()
    hh = now.strftime("%H")
    mm = now.strftime("%M")
    ss = now.strftime("%S")
    # Format sequence ID to be 2 digits with leading zero if needed
    id_str = str(seq_id).zfill(2)
    custom_header = f"{hh}{mm}{ss}{id_str}"
    return custom_header.encode('utf-8')

def start_client(pcap_file, server_ip="127.0.0.1", server_port=5300):
    """
    Parses a PCAP file for DNS queries, adds a custom header,
    and sends them to the server for resolution.
    """
    print(f"[*] Starting DNS Client...")
    print(f"[*] Reading packets from: {pcap_file}")
    print(f"[*] Server Address: {server_ip}:{server_port}\n")

    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[!] Error: PCAP file '{pcap_file}' not found.")
        return

    dns_queries = []
    # Filter for DNS query packets safely
    for packet in packets:
        dns_layer = packet.getlayer(DNS)
        if dns_layer and dns_layer.qr == 0 and dns_layer.qd:
            dns_queries.append(packet)

    if not dns_queries:
        print("[!] No DNS queries found in the specified PCAP file.")
        print("[!] This could be due to missing or malformed packets, or an Npcap installation issue.")
        return

    print(f"[*] Found {len(dns_queries)} DNS query packets.\n")
    print("-" * 60)
    print(f"{'Query Name':<35} | {'Custom Header':<15} | {'Resolved IP':<15}")
    print("-" * 60)

    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i, packet in enumerate(dns_queries):
        dns_layer = packet.getlayer(DNS)
        query_name = dns_layer.qd.qname.decode('utf-8')

        # 1. Create the custom header
        custom_header = create_custom_header(i)

        # 2. Extract original DNS packet bytes
        original_dns_packet = bytes(dns_layer)

        # 3. Prepend custom header to the DNS packet
        message_to_send = custom_header + original_dns_packet

        try:
            # 4. Send the modified packet to the server
            client_socket.sendto(message_to_send, (server_ip, server_port))

            # 5. Receive the response from the server
            response, _ = client_socket.recvfrom(1024)
            resolved_ip = response.decode('utf-8')

            # 6. Log the results
            print(f"{query_name:<35} | {custom_header.decode('utf-8'):<15} | {resolved_ip:<15}")

        except Exception as e:
            print(f"[!] An error occurred while communicating with the server: {e}")
            break

    client_socket.close()
    print("\n[*] Client finished execution.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="DNS Client to send queries from a PCAP file.")
    parser.add_argument("--pcap_file", required=True, help="The pcap file to process.")
    args = parser.parse_args()
    start_client(args.pcap_file)
