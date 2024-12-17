from scapy.all import IP, IPv6, TCP, UDP, PcapReader
from tqdm import tqdm
import time

def analyze_ports_and_protocols(pcap_file):
    start_time = time.time()

    tcp_80_count = set()
    tcp_443_count = set()
    udp_443_count = set()
    http_count = set()
    https_count = set()

    with PcapReader(pcap_file) as reader:
        progress = tqdm(desc="Processing packets", unit="pkt")

        for packet in reader:
            if IP in packet or IPv6 in packet:
                src_ip = packet[IP].src if IP in packet else packet[IPv6].src
                dst_ip = packet[IP].dst if IP in packet else packet[IPv6].dst

                if TCP in packet:
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport

                    if dport == 80 or sport == 80:  # HTTP
                        http_count.add((src_ip, sport, dst_ip, dport))
                        tcp_80_count.add((src_ip, sport, dst_ip, dport))

                    if dport == 443 or sport == 443:  # HTTPS
                        https_count.add((src_ip, sport, dst_ip, dport))
                        tcp_443_count.add((src_ip, sport, dst_ip, dport))

                elif UDP in packet:
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport

                    if dport == 443 or sport == 443:  # UDP 443
                        udp_443_count.add((src_ip, sport, dst_ip, dport))

            progress.update(1)

        progress.close()

    print(f"Processing complete. Time elapsed: {time.time() - start_time:.2f} seconds")
    print(tcp_443_count)
    print(f"Unique TCP Port 80 Connections (HTTP): {len(tcp_80_count)}")
    print(f"Unique TCP Port 443 Connections (HTTPS): {len(tcp_443_count)}")
    print(f"Unique UDP Port 443 Connections: {len(udp_443_count)}")
    print(f"Unique HTTP Connections: {len(http_count)}")
    print(f"Unique HTTPS Connections: {len(https_count)}")

if __name__ == "__main__":
    pcap_file = "split_trace_2019.pcap"
    analyze_ports_and_protocols(pcap_file)
