from scapy.all import PcapReader, TCP, UDP, Raw
from scapy.layers.inet import IP
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ALPN
from collections import defaultdict
import re
from scapy.all import *
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello

from tqdm import tqdm


def detect_http2(packet):
    if packet.haslayer(TLS):
        tls_layer = packet[TLS]
        if tls_layer.haslayer(TLSClientHello):
            extensions = tls_layer[TLSClientHello].ext 
            for ext in extensions:
                if hasattr(ext, "type") and ext.type == 16:  
                    if hasattr(ext, "data") and b"h2" in ext.data:
                        print("HTTP/2 detected (TLS ALPN)")
                        return True
    
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        if raw_data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
            print("HTTP/2 detected (Magic String)")
            return True

    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        if len(raw_data) >= 9:
            frame_type = raw_data[3]  
            if frame_type in [0, 1, 4, 6]: 
                # print("Possible HTTP/2 frame detected")
                return True

    # print("No HTTP/2 detected in this packet.")
    return False

def analyze_http_connections(pcap_file):
    http1=0 
    http2=0
    http2_new=0
    http3=0
    ip = 0
    http1_connections = set()
    http2_connections = set()
    http3_connections = set()
    with PcapReader(pcap_file) as packets:
        progress = tqdm(desc="Analyzing packets", unit="pkt")
        for packet in packets:
            if IP in packet:   
                ip+=1   
                if TCP in packet and packet[TCP].dport in [80, 8080]:
                    conn_tuple = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
                    http1_connections.add(conn_tuple) 
                    http1+=1
                elif TCP in packet and packet[TCP].dport == 443:
                    conn_tuple = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
                    http2_connections.add(conn_tuple)
                    http2+=1        

                elif UDP in packet and packet[UDP].dport == 443:
                    conn_tuple = (packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport)
                    http3_connections.add(conn_tuple)
                    http3+=1
            progress.update(1)
        progress.close()

    print(f"Count of HTTP/1 Connections: {len(http1_connections)}")
    print(f"Count of HTTP/2 Connections: {len(http2_connections)}")
    print(f"Count of HTTP/3 (QUIC) Connections: {len(http3_connections)}")
    
    print("====")
    print(http1,http2,http2_new ,http3,ip)
    # print(http2_connections)
if __name__ == "__main__":
    pcap_file = "split_trace_2019.pcap"
    analyze_http_connections(pcap_file)
