from scapy.all import PcapReader, TCP, UDP, Raw
from scapy.layers.inet import IP
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ALPN
from collections import defaultdict
import re

from tqdm import tqdm

def analyze_http_connections(pcap_file):
    http1_connections = set()
    http2_connections = set()
    http3_connections = set()
    with PcapReader(pcap_file) as packets:
        progress = tqdm(desc="Analyzing packets", unit="pkt")
        for packet in packets:
            if IP in packet:   
                if TCP in packet and packet[TCP].dport in [80, 8080]:
                    conn_tuple = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
                    http1_connections.add(conn_tuple) 

                elif TCP in packet and packet[TCP].dport == 443:
                    conn_tuple = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
                    http2_connections.add(conn_tuple)

                elif UDP in packet and packet[UDP].dport == 443:
                    conn_tuple = (packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport)
                    http3_connections.add(conn_tuple)

            progress.update(1)
        progress.close()

    print(f"Count of HTTP/1 Connections: {len(http1_connections)}")
    print(f"Count of HTTP/2 Connections: {len(http2_connections)}")
    print(f"Count of HTTP/3 (QUIC) Connections: {len(http3_connections)}")


if __name__ == "__main__":
    pcap_file = "split_trace_1.pcap"
    analyze_http_connections(pcap_file)
