from scapy.all import rdpcap, IP, IPv6, Ether, TCP, UDP, ICMP
import pandas as pd
import time
def analyze_ip_headers(pcap_file):
    start_time = time.time()    
    packets = rdpcap(pcap_file)
    data = []  

    for i, packet in enumerate(packets):        
        packet_info = {"Packet Number": i + 1}
        
        if Ether in packet:
            ether_layer = packet[Ether]
            packet_info["Source MAC"] = ether_layer.src
            packet_info["Destination MAC"] = ether_layer.dst
            packet_info["EtherType"] = hex(ether_layer.type)
        else:
            packet_info["Source MAC"] = None
            packet_info["Destination MAC"] = None
        
        if IP in packet:
            ip_layer = packet[IP]
            packet_info["IP Version"] = "IPv4"
            packet_info["Source IP"] = ip_layer.src
            packet_info["Destination IP"] = ip_layer.dst
            packet_info["Header Length (bytes)"] = ip_layer.ihl * 4
            packet_info["Total Length (bytes)"] = ip_layer.len
            packet_info["TTL"] = ip_layer.ttl
            packet_info["Protocol"] = ip_layer.proto
            packet_info["Checksum"] = ip_layer.chksum
            packet_info["Flags"] = str(ip_layer.flags)
            packet_info["Fragment Offset"] = ip_layer.frag
            packet_info["Identification"] = ip_layer.id
        else:
            packet_info["IP Version"] = None
        
        if IPv6 in packet:
            ipv6_layer = packet[IPv6]
            packet_info["IP Version"] = "IPv6"
            packet_info["Source IP"] = ipv6_layer.src
            packet_info["Destination IP"] = ipv6_layer.dst
            packet_info["Traffic Class"] = ipv6_layer.tc
            packet_info["Flow Label"] = ipv6_layer.fl
            packet_info["Payload Length (bytes)"] = ipv6_layer.plen
            packet_info["Next Header"] = ipv6_layer.nh
            packet_info["Hop Limit"] = ipv6_layer.hlim
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_info["Source Port"] = tcp_layer.sport
            packet_info["Destination Port"] = tcp_layer.dport
            packet_info["Sequence Number"] = tcp_layer.seq
            packet_info["Acknowledgment Number"] = tcp_layer.ack
            packet_info["TCP Flags"] = str(tcp_layer.flags)
            packet_info["Window Size"] = tcp_layer.window
            packet_info["Checksum"] = tcp_layer.chksum
            packet_info["Urgent Pointer"] = tcp_layer.urgptr
            # print(tcp_layer.options)
        if UDP in packet:
            udp_layer = packet[UDP]
            packet_info["Source Port"] = udp_layer.sport
            packet_info["Destination Port"] = udp_layer.dport
            packet_info["Length"] = udp_layer.len
            packet_info["Checksum"] = udp_layer.chksum
            #data/payload
        
        if ICMP in packet:
            icmp_layer = packet[ICMP]
            packet_info["ICMP Type"] = icmp_layer.type
            packet_info["ICMP Code"] = icmp_layer.code
            packet_info["Checksum"] = icmp_layer.chksum
            packet_info["ICMP ID"] = icmp_layer.id
            packet_info["ICMP Sequence"] = icmp_layer.seq
        
        data.append(packet_info)
    
    df = pd.DataFrame(data)
    
    csv_file = 'packet_analysis.csv'
    df.to_csv(csv_file, index=False)
    
    print("DataFrame:")
    print(df.head())
    print(f"Time spent: {time.time() - start_time} seconds")


# def analyse_ether(pcap_file):    
#     packets = rdpcap(pcap_file)
#     for i, packet in enumerate(packets):
#         if i > 1:    break
#         if Ether in packet:
#             ether_layer = packet[Ether]            
#             print(ether_layer.show())

if __name__ == "__main__":    
    pcap_file = "router-1.pcap"    
    analyze_ip_headers(pcap_file)
