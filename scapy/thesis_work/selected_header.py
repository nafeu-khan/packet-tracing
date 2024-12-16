from scapy.all import IP, IPv6, TCP, UDP, ICMP, SCTP, PcapReader
from tqdm import tqdm
import csv
import time

global pre_url
pre_url = "./selected_headers_file/"

def analyze_selected_headers(pcap_file):
    start_time = time.time()

    tcp_connections = set()
    sctp_connections = set()

    csv_configs = {
        "ipv4_headers.csv": {
            "fieldnames": [
                "Packet Number", "Source IP", "Destination IP", "IHL(byte)", "DSCP", "ECN", "Protocol"
            ]
        },
        "ipv6_headers.csv": {
            "fieldnames": [
                "Packet Number", "Source IP", "Destination IP", "Flow Label", "Traffic Class", "Next Header"
            ]
        },
        "tcp_headers.csv": {
            "fieldnames": [
                "Packet Number", "Source IP", "Destination IP", "Reserved", "CWR", "ECE", "Timestamp Value"
            ]
        },
        "udp_headers.csv": {
            "fieldnames": [
                "Packet Number", "UDP Length"
            ]
        },
        "icmp_headers.csv": {
            "fieldnames": [
                "Packet Number", "ICMP Type"
            ]
        },
        "sctp_headers.csv": {
            "fieldnames": [
                "Packet Number", "Source Port", "Destination Port", "Verification Tag", "Checksum"
            ]
        },
        "other_packets.csv": {
            "fieldnames": [
                "Packet Number"
            ]
        }
    }

    summary_counts = {
        "Total Packets": 0,
        "IPv4 Packets": 0,
        "IPv6 Packets": 0,
        "TCP Packets": 0,
        "UDP Packets": 0,
        "ICMP Packets": 0,
        "SCTP Packets": 0,
        "TCP Connections": 0,
        "SCTP Connections": 0,
        "Other Protocols": 0
    }

    # Initialize dictionaries to store data in memory
    data_buffers = {key: [] for key in csv_configs.keys()}

    try:
        with PcapReader(pcap_file) as reader:
            progress = tqdm(desc="Reading packets", unit="pkt")

            for i, packet in enumerate(reader, start=1):
                summary_counts["Total Packets"] += 1
                packet_number = i

                if IP in packet:
                    summary_counts["IPv4 Packets"] += 1
                    ip_layer = packet[IP]
                    data_buffers["ipv4_headers.csv"].append({
                        "Packet Number": packet_number,
                        "Source IP": ip_layer.src,
                        "Destination IP": ip_layer.dst,
                        "IHL(byte)": ip_layer.ihl * 4, 
                        "DSCP": ip_layer.tos >> 2,
                        "ECN": ip_layer.tos & 3,
                        "Protocol": ip_layer.proto
                    })

                elif IPv6 in packet:
                    summary_counts["IPv6 Packets"] += 1
                    ipv6_layer = packet[IPv6]
                    data_buffers["ipv6_headers.csv"].append({
                        "Packet Number": packet_number,
                        "Source IP": ipv6_layer.src,
                        "Destination IP": ipv6_layer.dst,
                        "Flow Label": ipv6_layer.fl,
                        "Traffic Class": ipv6_layer.tc,
                        "Next Header": ipv6_layer.nh
                    })

                if TCP in packet:
                    summary_counts["TCP Packets"] += 1
                    tcp_layer = packet[TCP]

                    if tcp_layer.flags == 18:  # SYN-ACK
                        if IP in packet:
                            tcp_connections.add((packet[IP].src, tcp_layer.sport, packet[IP].dst, tcp_layer.dport))
                        elif IPv6 in packet:
                            tcp_connections.add((packet[IPv6].src, tcp_layer.sport, packet[IPv6].dst, tcp_layer.dport))

                    for option in packet['TCP'].options:
                        if option[0] == 'Timestamp':
                            TimestampValue = f"{option[1][0]}, Timestamp Echo Reply: {option[1][1]}"
                            break
                    else:
                        TimestampValue = "-"

                    data_buffers["tcp_headers.csv"].append({
                        "Source IP": packet[IP].src if IP in packet else packet[IPv6].src,
                        "Destination IP": packet[IP].dst if IP in packet else packet[IPv6].dst,
                        "Packet Number": packet_number,
                        "Reserved": tcp_layer.reserved,
                        "CWR": bool(tcp_layer.flags & 0x80),
                        "ECE": bool(tcp_layer.flags & 0x40),
                        "Timestamp Value": TimestampValue
                    })

                elif UDP in packet:
                    summary_counts["UDP Packets"] += 1
                    udp_layer = packet[UDP]
                    data_buffers["udp_headers.csv"].append({
                        "Packet Number": packet_number,
                        "UDP Length": udp_layer.len
                    })

                elif ICMP in packet:
                    summary_counts["ICMP Packets"] += 1
                    icmp_layer = packet[ICMP]
                    data_buffers["icmp_headers.csv"].append({
                        "Packet Number": packet_number,
                        "ICMP Type": icmp_layer.type
                    })

                elif SCTP in packet:
                    summary_counts["SCTP Packets"] += 1
                    sctp_layer = packet[SCTP]

                    if IP in packet:
                        sctp_connections.add((packet[IP].src, sctp_layer.sport, packet[IP].dst, sctp_layer.dport))
                    elif IPv6 in packet:
                        sctp_connections.add((packet[IPv6].src, sctp_layer.sport, packet[IPv6].dst, sctp_layer.dport))

                    data_buffers["sctp_headers.csv"].append({
                        "Packet Number": packet_number,
                        "Source Port": sctp_layer.sport,
                        "Destination Port": sctp_layer.dport,
                        "Verification Tag": sctp_layer.tag,
                        "Checksum": sctp_layer.cksum
                    })

                else:
                    summary_counts["Other Protocols"] += 1
                    data_buffers["other_packets.csv"].append({
                        "Packet Number": packet_number
                    })

                progress.update(1)

            progress.close()

        summary_counts["TCP Connections"] = len(tcp_connections)
        summary_counts["SCTP Connections"] = len(sctp_connections)

        # Write accumulated data to CSV files
        for filename, rows in data_buffers.items():
            filepath = f"{pre_url}{filename}"
            with open(filepath, 'w', newline='', encoding='utf-8') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=csv_configs[filename]["fieldnames"])
                writer.writeheader()
                writer.writerows(rows)

        # Write summary file
        summary_filename = f"{pre_url}summary.csv"
        with open(summary_filename, 'w', newline='', encoding='utf-8') as summary_file:
            summary_writer = csv.DictWriter(summary_file, fieldnames=summary_counts.keys())
            summary_writer.writeheader()
            summary_writer.writerow(summary_counts)

        print(f"Packet reading finished. Total time spent: {time.time() - start_time:.2f} seconds")
        print(f"Total TCP connections: {len(tcp_connections)}")
        print(f"Total SCTP connections: {len(sctp_connections)}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    pcap_file = "200608241400.dump"
    analyze_selected_headers(pcap_file)
