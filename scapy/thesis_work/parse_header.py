from scapy.all import IP, IPv6, TCP, UDP, ICMP, SCTP, PcapReader, Raw
from tqdm import tqdm
import csv
import os
import time

# Folder to store the header files
header_info_folder = "./header_info/"
os.makedirs(header_info_folder, exist_ok=True)

def analyze_selected_headers(pcap_file):
    start_time = time.time()

    # Define separate CSV files and their column configurations
    csv_configs = {
        "ip.csv": {
            "fieldnames": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                           "IHL(byte)", "DSCP", "ECN", "Protocol", "Packet Length"]
        },
        "ip_tcp.csv": {
            "fieldnames": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                           "IHL(byte)", "DSCP", "ECN", "Protocol", "Packet Length", 
                           "TCP-Reserved", "TCP-CWR", "TCP-ECE", "TCP-Timestamp_Value"]
        },
        "ip_udp.csv": {
            "fieldnames": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                           "IHL(byte)", "DSCP", "ECN", "Protocol", "Packet Length", "UDP_Length"]
        },
        "ip_icmp.csv": {
            "fieldnames": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                           "IHL(byte)", "DSCP", "ECN", "Protocol", "Packet Length", "ICMP_Type"]
        },
        "ip_sctp.csv": {
            "fieldnames": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                           "IHL(byte)", "DSCP", "ECN", "Protocol", "Packet Length", 
                           "SCTP-Verification_Tag", "SCTP-Checksum"]
        },
        "ipv6.csv": {
            "fieldnames": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                           "Flow Label", "Traffic Class", "Next Header", "Packet Length"]
        },
        "ipv6_tcp.csv": {
            "fieldnames": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                           "Flow Label", "Traffic Class", "Next Header", "Packet Length", 
                           "TCP-Reserved", "TCP-CWR", "TCP-ECE", "TCP-Timestamp_Value"]
        },
        "ipv6_udp.csv": {
            "fieldnames": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                           "Flow Label", "Traffic Class", "Next Header", "Packet Length", "UDP_Length"]
        },
        "ipv6_icmp.csv": {
            "fieldnames": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                           "Flow Label", "Traffic Class", "Next Header", "Packet Length", "ICMP_Type"]
        },
        "ipv6_sctp.csv": {
            "fieldnames": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                           "Flow Label", "Traffic Class", "Next Header", "Packet Length", 
                           "SCTP-Verification_Tag", "SCTP-Checksum"]
        },
        # Add the HTTP detection results
        "http_connections.csv": {
            "fieldnames": ["HTTP/1.x", "HTTP/2", "HTTP/3"]
        }
    }

    # Initialize data buffers
    data_buffers = {key: [] for key in csv_configs.keys()}

    # HTTP connection counters
    http_counts = {"HTTP/1.x": 0, "HTTP/2": 0, "HTTP/3": 0}

    try:
        with PcapReader(pcap_file) as reader:
            progress = tqdm(desc="Reading packets", unit="pkt")

            for i, packet in enumerate(reader, start=1):
                packet_number = i

                src_port = "-"
                dst_port = "-"

                if packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(SCTP):
                    transport_layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP] if packet.haslayer(UDP) else packet[SCTP]
                    src_port = transport_layer.sport
                    dst_port = transport_layer.dport

                if IP in packet:
                    ip_layer = packet[IP]
                    base_data = {
                        "Packet Number": packet_number,
                        "Source IP": ip_layer.src,
                        "Destination IP": ip_layer.dst,
                        "Source Port": src_port,
                        "Destination Port": dst_port,
                        "IHL(byte)": ip_layer.ihl * 4,
                        "DSCP": ip_layer.tos >> 2,
                        "ECN": ip_layer.tos & 3,
                        "Protocol": ip_layer.proto,
                        "Packet Length": f"{ip_layer.len}" # header len only -> {len(ip_layer)}+
                    }
                    # Add to IP base CSV
                    data_buffers["ip.csv"].append(base_data)

                    if TCP in packet:
                        tcp_layer = packet[TCP]
                        tcp_data = base_data.copy()
                        tcp_data.update({
                            "TCP-Reserved": tcp_layer.reserved,
                            "TCP-CWR": bool(tcp_layer.flags & 0x80),
                            "TCP-ECE": bool(tcp_layer.flags & 0x40),
                            "TCP-Timestamp_Value": next((f"{opt[1][0]}, {opt[1][1]}" for opt in tcp_layer.options if opt[0] == 'Timestamp'), "-")
                        })
                        data_buffers["ip_tcp.csv"].append(tcp_data)

                    elif UDP in packet:
                        udp_layer = packet[UDP]
                        udp_data = base_data.copy()
                        udp_data["UDP_Length"] = udp_layer.len
                        data_buffers["ip_udp.csv"].append(udp_data)

                    elif ICMP in packet:
                        icmp_layer = packet[ICMP]
                        icmp_data = base_data.copy()
                        icmp_data["ICMP_Type"] = icmp_layer.type
                        data_buffers["ip_icmp.csv"].append(icmp_data)
                    elif SCTP in packet:
                        sctp_layer = packet[SCTP]
                        sctp_data = base_data.copy()
                        sctp_data.update({
                            "SCTP-Verification_Tag": sctp_layer.tag,
                            "SCTP-Checksum": sctp_layer.cksum
                        })
                        data_buffers["ip_sctp.csv"].append(sctp_data)

                elif IPv6 in packet:
                    ipv6_layer = packet[IPv6]
                    base_data = {
                        "Packet Number": packet_number,
                        "Source IP": ipv6_layer.src,
                        "Destination IP": ipv6_layer.dst,
                        "Source Port": src_port,
                        "Destination Port": dst_port,
                        "Flow Label": ipv6_layer.fl,
                        "Traffic Class": ipv6_layer.tc,
                        "Next Header": ipv6_layer.nh,
                        "Packet Length": f"{len(ipv6_layer)}+{ipv6_layer.plen}" # header len only -> {len(ipv6_layer)}+ only paylaod len -> {ipv6_layer.plen}
                    }

                    # Add to IPv6 base CSV
                    data_buffers["ipv6.csv"].append(base_data)

                    if TCP in packet:
                        tcp_layer = packet[TCP]
                        tcp_data = base_data.copy()
                        tcp_data.update({
                            "TCP-Reserved": tcp_layer.reserved,
                            "TCP-CWR": bool(tcp_layer.flags & 0x80),
                            "TCP-ECE": bool(tcp_layer.flags & 0x40),
                            "TCP-Timestamp_Value": next((f"{opt[1][0]}, {opt[1][1]}" for opt in tcp_layer.options if opt[0] == 'Timestamp'), "-")
                        })
                        data_buffers["ipv6_tcp.csv"].append(tcp_data)

                    elif UDP in packet:
                        udp_layer = packet[UDP]
                        udp_data = base_data.copy()
                        udp_data["UDP_Length"] = udp_layer.len
                        data_buffers["ipv6_udp.csv"].append(udp_data)

                    elif ICMP in packet:
                        icmp_layer = packet[ICMP]
                        icmp_data = base_data.copy()
                        icmp_data["ICMP_Type"] = icmp_layer.type
                        data_buffers["ipv6_icmp.csv"].append(icmp_data)

                    elif SCTP in packet:
                        sctp_layer = packet[SCTP]
                        sctp_data = base_data.copy()
                        sctp_data.update({
                            "SCTP-Verification_Tag": sctp_layer.tag,
                            "SCTP-Checksum": sctp_layer.cksum
                        })
                        data_buffers["ipv6_sctp.csv"].append(sctp_data)
                    # Detect HTTP connections
                    if packet.haslayer(TCP):
                        # Check for HTTP/1.x
                        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                            if packet.haslayer(Raw):
                                payload = bytes(packet[Raw].load)
                                print(f"Packet {packet_number} payload: {payload}")
                                if b"HTTP/1.1" in payload:
                                    print(f"HTTP/1 detected in packet {packet_number}")
                                    http_counts["HTTP/1.x"] += 1

                        # Check for HTTP/2 (TLS on port 443)
                        elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                            if packet.haslayer(Raw):
                                payload = bytes(packet[Raw].load)
                                print(f"Packet {packet_number} payload: {payload}")
                                if b"h2" in payload:  # ALPN negotiation for HTTP/2
                                    print(f"HTTP/2 detected in packet {packet_number}")
                                    http_counts["HTTP/2"] += 1

                    elif packet.haslayer(UDP):
                        # Check for HTTP/3 (QUIC)
                        if packet[UDP].dport == 443 or packet[UDP].sport == 443:
                            if packet.haslayer(Raw):
                                payload = bytes(packet[Raw].load)
                                print(f"Packet {packet_number} payload: {payload}")
                                if b"quic" in payload.lower():
                                    print(f"HTTP/3 detected in packet {packet_number}")
                                    http_counts["HTTP/3"] += 1

                progress.update(1)

            progress.close()

        # Append the HTTP connection counts to the HTTP CSV
        data_buffers["http_connections.csv"].append(http_counts)

        # Write accumulated data to separate CSV files
        for filename, rows in data_buffers.items():
            filepath = os.path.join(header_info_folder, filename)
            with open(filepath, 'w', newline='', encoding='utf-8') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=csv_configs[filename]["fieldnames"])
                writer.writeheader()
                writer.writerows(rows)

        print(f"Packet analysis completed. Time taken: {time.time() - start_time:.2f} seconds.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # pcap_file = "200608241400.dump"
    pcap_file = "split_trace_2019.pcap"
    analyze_selected_headers(pcap_file)
