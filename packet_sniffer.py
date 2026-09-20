# Network Packet Sniffer - Raw Socket + IP/TCP/UDP Parser
# Note: Real sniffing needs admin/root: sudo python packet_sniffer.py
# For demo without root, we simulate packet log

import socket
import struct
import textwrap
from datetime import datetime
from collections import Counter

# Stats for Step 4
stats = Counter()
LOG_FILE = "network_log.txt"

def log_traffic(msg):
    print(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def parse_ip_header(data):
    # Step 2: Parse IP header (Source IP, Dest IP, Protocol)
    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = iph[0]
    ttl = iph[5]
    protocol = iph[6]
    src = socket.inet_ntoa(iph[8])
    dst = socket.inet_ntoa(iph[9])
    return src, dst, protocol, ttl, data[20:]

def parse_tcp_header(data):
    # Step 3: Decode TCP ports and payload
    tcph = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcph[0]
    dst_port = tcph[1]
    return src_port, dst_port, data[20:]

def parse_udp_header(data):
    # Step 3: Decode UDP
    udph = struct.unpack('!HHHH', data[:8])
    src_port = udph[0]
    dst_port = udph[1]
    return src_port, dst_port, data[8:]

def main():
    print("=== Network Packet Sniffer ===")
    open(LOG_FILE, "w").write(f"Sniff started at {datetime.now()}\n")

    # Step 1: Create raw socket listener
    try:
        # This requires root/admin
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind(("0.0.0.0", 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) if hasattr(conn, 'ioctl') else None
        print("[*] Raw socket listening... (Press Ctrl+C to stop)")

        packet_count = 0
        while packet_count < 10: # Capture 10 packets for demo
            raw_data, addr = conn.recvfrom(65536)
            src, dst, proto, ttl, payload = parse_ip_header(raw_data)

            proto_name = {1:"ICMP", 6:"TCP", 17:"UDP"}.get(proto, str(proto))
            stats[proto_name] += 1

            msg = f"[IP] {src} -> {dst} | Proto: {proto_name} | TTL: {ttl}"

            if proto == 6: # TCP
                s_port, d_port, tcp_payload = parse_tcp_header(payload)
                msg += f" | TCP {s_port}->{d_port} | Payload: {len(tcp_payload)} bytes"
            elif proto == 17: # UDP
                s_port, d_port, udp_payload = parse_udp_header(payload)
                msg += f" | UDP {s_port}->{d_port} | Payload: {len(udp_payload)} bytes"

            log_traffic(msg)
            packet_count += 1

    except PermissionError:
        # Fallback simulation for Workora submission without root
        print("[!] Root privileges required for raw socket. Running SIMULATION mode for demo...")
        simulated_packets = [
            "[IP] 192.168.1.5 -> 8.8.8.8 | Proto: TCP | TTL: 64 | TCP 54321->80 | Payload: 48 bytes",
            "[IP] 8.8.8.8 -> 192.168.1.5 | Proto: TCP | TTL: 54 | TCP 80->54321 | Payload: 128 bytes",
            "[IP] 192.168.1.5 -> 1.1.1.1 | Proto: UDP | TTL: 64 | UDP 53123->53 | Payload: 32 bytes (DNS Query)",
            "[IP] 192.168.1.10 -> 192.168.1.5 | Proto: ICMP | TTL: 64",
        ]
        for pkt in simulated_packets:
            stats[pkt.split("Proto:")[1].split("|")[0].strip()] += 1
            log_traffic(pkt)
        print("[+] Simulated 4 packets logged")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        # Step 4: Log traffic summary statistics
        print("\n=== Step 4: Traffic Summary ===")
        summary = f"\n--- Summary at {datetime.now()} ---\nTotal Packets: {sum(stats.values())}\n"
        for proto, count in stats.items():
            summary += f"{proto}: {count}\n"
        print(summary)
        with open(LOG_FILE, "a") as f:
            f.write(summary)
        print(f"[+] Log saved to {LOG_FILE}")

if __name__ == "__main__":
    main()
