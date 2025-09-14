import socket
import json
from datetime import datetime
from scapy.all import DNS

# --- Server Configuration ---
# A pool of 15 IP addresses for load balancing.
IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

def load_rules(file_path="rules.json"):
    """Loads the routing rules from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: Rules file '{file_path}' not found.")
        return None
    except json.JSONDecodeError:
        print(f"[!] Error: Could not decode JSON from '{file_path}'.")
        return None

def get_time_period_rule(hour, rules):
    """Determines the correct rule set based on the hour."""
    time_based_rules = rules.get("timestamp_rules", {}).get("time_based_routing", {})
    for period, rule in time_based_rules.items():
        try:
            start_str, end_str = rule["time_range"].split('-')
            start_hour = int(start_str.split(':')[0])
            end_hour = int(end_str.split(':')[0])

            # Handle overnight ranges (e.g., 20:00-03:59)
            if start_hour > end_hour:
                if hour >= start_hour or hour <= end_hour:
                    return rule
            else: # Handle normal daytime ranges
                if start_hour <= hour <= end_hour:
                    return rule
        except (ValueError, KeyError) as e:
            print(f"[!] Error processing rule for '{period}': {e}")
            continue
    return None

def resolve_ip_address(custom_header, rules):
    """
    Selects an IP address from the pool based on the custom header
    and the loaded rules.
    """
    if not rules:
        return "10.0.0.1" # Default error IP if rules are missing

    try:
        # 1. Extract hour and ID from the custom header "HHMMSSID"
        hour = int(custom_header[0:2])
        session_id = int(custom_header[6:8])

        # 2. Determine the correct time period and get its rules
        rule = get_time_period_rule(hour, rules)

        if not rule:
            print(f"[!] No matching time rule found for hour {hour}.")
            return "10.0.0.2" # Default error IP for no rule match

        # 3. Use the rule to calculate the IP index
        hash_mod = rule.get("hash_mod", 5)
        ip_pool_start = rule.get("ip_pool_start", 0)

        # 4. Calculate final index
        final_index = ip_pool_start + (session_id % hash_mod)

        # 5. Select IP from the pool, with a fallback
        if 0 <= final_index < len(IP_POOL):
            return IP_POOL[final_index]
        else:
            print(f"[!] Calculated index {final_index} is out of bounds for the IP Pool.")
            return "10.0.0.3" # Default error IP for out-of-bounds index

    except (ValueError, IndexError) as e:
        print(f"[!] Error parsing custom header '{custom_header}': {e}")
        return "10.0.0.4" # Default error IP for parsing failure

def start_server(host="127.0.0.1", port=5300):
    """
    Starts the DNS server, loads rules, and processes incoming requests.
    """
    rules = load_rules()
    if not rules:
        print("[!] Server cannot start without valid rules.")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((host, port))
        print(f"[*] DNS Server started successfully.")
        print(f"[*] Listening on {host}:{port}\n")
    except Exception as e:
        print(f"[!] Failed to start server: {e}")
        return

    print("-" * 70)
    print(f"{'Client Address':<20} | {'Header':<10} | {'Domain Name':<25} | {'Resolved IP':<15}")
    print("-" * 70)

    try:
        while True:
            message, client_address = server_socket.recvfrom(1024)
            custom_header = message[:8].decode('utf-8')
            original_dns_packet = message[8:]

            # Extract domain name for logging purposes
            try:
                domain_name = DNS(original_dns_packet).qd.qname.decode('utf-8')
            except:
                domain_name = "N/A"

            # Resolve IP using the new algorithm
            resolved_ip = resolve_ip_address(custom_header, rules)

            print(f"{str(client_address):<20} | {custom_header:<10} | {domain_name:<25} | {resolved_ip:<15}")
            server_socket.sendto(resolved_ip.encode('utf-8'), client_address)

    except KeyboardInterrupt:
        print("\n[*] Server is shutting down.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()

