import pyshark
import csv
import time
from tqdm import tqdm

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
                "Packet Number", "Source IP", "Destination IP", "Reserved", "CWR", "ECE"
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
    
    csv_files = {}
    csv_writers = {}

    try:
        # Initialize CSV writers
        for filename, config in csv_configs.items():
            csv_file = open(filename, 'w', newline='', encoding='utf-8')
            writer = csv.DictWriter(csv_file, fieldnames=config["fieldnames"])
            writer.writeheader()
            csv_files[filename] = csv_file
            csv_writers[filename] = writer

        summary_filename = "summary.csv"
        summary_file = open(summary_filename, 'w', newline='', encoding='utf-8')
        summary_writer = csv.DictWriter(summary_file, fieldnames=summary_counts.keys())
        summary_writer.writeheader()

        capture = pyshark.FileCapture(pcap_file)
        
        progress = tqdm(desc="Reading packets", unit="pkt")

        for i, packet in enumerate(capture, start=1):
            summary_counts["Total Packets"] += 1
            packet_number = i

            if hasattr(packet, 'ip'):
                summary_counts["IPv4 Packets"] += 1
                csv_writers["ipv4_headers.csv"].writerow({
                    "Packet Number": packet_number,
                    "Source IP": packet.ip.src,
                    "Destination IP": packet.ip.dst,
                    "IHL(byte)": int(packet.ip.hdr_len),
                    "DSCP": int(packet.ip.dsfield_dscp),
                    "ECN": int(packet.ip.dsfield_ecn),
                    "Protocol": packet.ip.proto
                })

            elif hasattr(packet, 'ipv6'):
                summary_counts["IPv6 Packets"] += 1
                csv_writers["ipv6_headers.csv"].writerow({
                    "Packet Number": packet_number,
                    "Source IP": packet.ipv6.src,
                    "Destination IP": packet.ipv6.dst,
                    "Flow Label": packet.ipv6.flow,
                    "Traffic Class": packet.ipv6.tclass,
                    "Next Header": packet.ipv6.nxt
                })

            if hasattr(packet, 'tcp'):
                summary_counts["TCP Packets"] += 1
                
                # Check for SYN-ACK flag combination
                if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '1':
                    src_ip = packet.ip.src if hasattr(packet, 'ip') else packet.ipv6.src
                    dst_ip = packet.ip.dst if hasattr(packet, 'ip') else packet.ipv6.dst
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                    tcp_connections.add((src_ip, src_port, dst_ip, dst_port))

                csv_writers["tcp_headers.csv"].writerow({
                    "Packet Number": packet_number,
                    "Source IP": packet.ip.src if hasattr(packet, 'ip') else packet.ipv6.src,
                    "Destination IP": packet.ip.dst if hasattr(packet, 'ip') else packet.ipv6.dst,
                    "Reserved": getattr(packet.tcp, 'res', 'N/A'),
                    "CWR": getattr(packet.tcp, 'flags_cwr', '0'),
                    "ECE": getattr(packet.tcp, 'flags_ece', '0')
                })

            elif hasattr(packet, 'udp'):
                summary_counts["UDP Packets"] += 1
                csv_writers["udp_headers.csv"].writerow({
                    "Packet Number": packet_number,
                    "UDP Length": packet.udp.length
                })

            elif hasattr(packet, 'icmp'):
                summary_counts["ICMP Packets"] += 1
                csv_writers["icmp_headers.csv"].writerow({
                    "Packet Number": packet_number,
                    "ICMP Type": packet.icmp.type
                })

            elif hasattr(packet, 'sctp'):
                summary_counts["SCTP Packets"] += 1
                src_ip = packet.ip.src if hasattr(packet, 'ip') else packet.ipv6.src
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else packet.ipv6.dst
                sctp_connections.add((src_ip, packet.sctp.srcport, dst_ip, packet.sctp.dstport))

                csv_writers["sctp_headers.csv"].writerow({
                    "Packet Number": packet_number,
                    "Source Port": packet.sctp.srcport,
                    "Destination Port": packet.sctp.dstport,
                    "Verification Tag": packet.sctp.verification_tag,
                    "Checksum": packet.sctp.checksum
                })

            else:
                summary_counts["Other Protocols"] += 1
                csv_writers["other_packets.csv"].writerow({
                    "Packet Number": packet_number,
                })

            progress.update(1)

        progress.close()
        capture.close()

        # Summarize the connection counts
        summary_counts["TCP Connections"] = len(tcp_connections)
        summary_counts["SCTP Connections"] = len(sctp_connections)

        # Write summary counts to summary.csv
        summary_writer.writerow(summary_counts)
        print(f"Packet reading finished. Total time spent: {time.time() - start_time:.2f} seconds")
        print(f"Total TCP connections: {len(tcp_connections)}")
        print(f"Total SCTP connections: {len(sctp_connections)}")

    finally:
        for csv_file in csv_files.values():
            csv_file.close()
        if summary_file:
            summary_file.close()

if __name__ == "__main__":
    pcap_file = "split_trace_1.pcap"
    analyze_selected_headers(pcap_file)
