from scapy.all import IP, IPv6, TCP, UDP, ICMP, SCTP, PcapReader
from tqdm import tqdm
import csv
import time

def analyze_selected_headers(pcap_file):
    start_time = time.time()
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
                "Packet Number", "Reserved", "CWR", "ECE"
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
        
        with PcapReader(pcap_file) as reader, tqdm(desc="Reading packets", unit="pkt") as progress:
            for i, packet in enumerate(reader, start=1):
                summary_counts["Total Packets"] += 1
                has_protocol = False 
                           
                if IP in packet:
                    summary_counts["IPv4 Packets"] += 1
                    has_protocol = True
                    ip_layer = packet[IP]
                    ipv4_info = {
                        "Packet Number": i,
                        "Source IP": ip_layer.src,
                        "Destination IP": ip_layer.dst,
                        "IHL(byte)": ip_layer.ihl * 4 if ip_layer.ihl else None,
                        "DSCP": ip_layer.tos >> 2 if hasattr(ip_layer, 'tos') else None,
                        "ECN": ip_layer.tos & 3 if hasattr(ip_layer, 'tos') else None,
                        "Protocol": ip_layer.proto
                    }
                    csv_writers["ipv4_headers.csv"].writerow(ipv4_info)
                            
                if IPv6 in packet:
                    summary_counts["IPv6 Packets"] += 1
                    has_protocol = True
                    ipv6_layer = packet[IPv6]
                    ipv6_info = {
                        "Packet Number": i,
                        "Source IP": ipv6_layer.src,
                        "Destination IP": ipv6_layer.dst,
                        "Flow Label": ipv6_layer.fl if hasattr(ipv6_layer, 'fl') else None,
                        "Traffic Class": ipv6_layer.tc if hasattr(ipv6_layer, 'tc') else None,
                        "Next Header": ipv6_layer.nh if hasattr(ipv6_layer, 'nh') else None
                    }
                    csv_writers["ipv6_headers.csv"].writerow(ipv6_info)
                            
                if TCP in packet:
                    summary_counts["TCP Packets"] += 1
                    has_protocol = True
                    tcp_layer = packet[TCP]
                    tcp_info = {
                        "Packet Number": i,
                        "Reserved": tcp_layer.reserved if hasattr(tcp_layer, 'reserved') else None,
                        "CWR": bool(tcp_layer.flags & 0x80),
                        "ECE": bool(tcp_layer.flags & 0x40)
                    }
                    csv_writers["tcp_headers.csv"].writerow(tcp_info)
                            
                if UDP in packet:
                    summary_counts["UDP Packets"] += 1
                    has_protocol = True
                    udp_layer = packet[UDP]
                    udp_info = {
                        "Packet Number": i,
                        "UDP Length": udp_layer.len if hasattr(udp_layer, 'len') else None
                    }
                    csv_writers["udp_headers.csv"].writerow(udp_info)
                     
                if ICMP in packet:
                    summary_counts["ICMP Packets"] += 1
                    has_protocol = True
                    icmp_layer = packet[ICMP]
                    icmp_info = {
                        "Packet Number": i,
                        "ICMP Type": icmp_layer.type if hasattr(icmp_layer, 'type') else None
                    }
                    csv_writers["icmp_headers.csv"].writerow(icmp_info)
                    
                if SCTP in packet:
                    summary_counts["SCTP Packets"] += 1
                    has_protocol = True
                    sctp_layer = packet[SCTP]
                    sctp_info = {
                        "Packet Number": i,
                        "Source Port": sctp_layer.sport,
                        "Destination Port": sctp_layer.dport,
                        "Verification Tag": sctp_layer.tag if hasattr(sctp_layer, 'tag') else None,
                        "Checksum": sctp_layer.cksum if hasattr(sctp_layer, 'cksum') else None
                    }
                    csv_writers["sctp_headers.csv"].writerow(sctp_info)
                    
                if not has_protocol:
                    summary_counts["Other Protocols"] += 1
                
                progress.update(1)
        
        summary_writer.writerow(summary_counts)
        
        print("Packet reading finished.")
        print(f"Data written to separate CSV files and {summary_filename}. Total time spent: {time.time() - start_time:.2f} seconds")
    
    finally:
       
        for csv_file in csv_files.values():
            csv_file.close()
        summary_file.close()

if __name__ == "__main__":
    pcap_file = "200608241400.dump"  
    analyze_selected_headers(pcap_file)