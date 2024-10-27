from scapy.all import IP, IPv6, TCP, UDP, ICMP, SCTP, PcapReader
from tqdm import tqdm
import csv
import time

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
                "Packet Number","Source IP","Destination IP", "Reserved", "CWR", "ECE"
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
        "TCP Connections":0,
        "SCTP Connections":0,
        "Other Protocols": 0
    }
    
    csv_files = {}
    csv_writers = {}

    try:
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

        with PcapReader(pcap_file) as reader:
            # batch_update = 10000
            progress = tqdm(desc="Reading packets", unit="pkt")#, total=batch_update)

            for i, packet in enumerate(reader, start=1):
                summary_counts["Total Packets"] += 1
                packet_number = i
                # if i > 1000000:
                #     break

                if IP in packet:
                    summary_counts["IPv4 Packets"] += 1
                    ip_layer = packet[IP]
                    csv_writers["ipv4_headers.csv"].writerow({
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
                    csv_writers["ipv6_headers.csv"].writerow({
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
                    
                    if IP in packet:
                        tcp_connections.add((packet[IP].src, tcp_layer.sport, packet[IP].dst, tcp_layer.dport))
                    elif IPv6 in packet:
                        tcp_connections.add((packet[IPv6].src, tcp_layer.sport, packet[IPv6].dst, tcp_layer.dport))
                    
                    csv_writers["tcp_headers.csv"].writerow({
                        "Source IP": packet[IP].src if IP in packet else packet[IPv6].src,
                        "Destination IP": packet[IP].dst if IP in packet else packet[IPv6].dst,
                        "Packet Number": packet_number,
                        "Reserved": tcp_layer.reserved,
                        "CWR": bool(tcp_layer.flags & 0x80),
                        "ECE": bool(tcp_layer.flags & 0x40)
                    })
                elif UDP in packet:
                        summary_counts["UDP Packets"] += 1
                        udp_layer = packet[UDP]
                        csv_writers["udp_headers.csv"].writerow({
                            "Packet Number": packet_number,
                            "UDP Length": udp_layer.len
                        })
                elif ICMP in packet:
                    summary_counts["ICMP Packets"] += 1
                    icmp_layer = packet[ICMP]
                    csv_writers["icmp_headers.csv"].writerow({
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
                    
                    csv_writers["sctp_headers.csv"].writerow({
                        "Packet Number": packet_number,
                        "Source Port": sctp_layer.sport,
                        "Destination Port": sctp_layer.dport,
                        "Verification Tag": sctp_layer.tag,
                        "Checksum": sctp_layer.cksum
                    })

                else:
                    summary_counts["Other Protocols"] += 1
                    csv_writers["other_packets.csv"].writerow({
                        "Packet Number": packet_number,
                    })

                # if i % batch_update == 0:
                progress.update(1)

            progress.close()

        summary_counts["TCP Connections"] = len(tcp_connections)
        summary_counts["SCTP Connections"] = len(sctp_connections)
        
        summary_writer.writerow(summary_counts)
        print(f"Packet reading finished. Total time spent: {time.time() - start_time:.2f} seconds")
        print(f"Total TCP connections: {len(tcp_connections)}")
        print(f"Total SCTP connections: {len(sctp_connections)}")

    finally:
        for csv_file in csv_files.values():
            csv_file.close()
        summary_file.close()

if __name__ == "__main__":
    pcap_file = "split_trace_1.pcap" 
    analyze_selected_headers(pcap_file)
