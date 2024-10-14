from scapy.all import IP, IPv6, Ether, TCP, UDP, ICMP, Dot1Q, PPPoE, PcapReader, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.contrib.mpls import MPLS

from scapy.contrib.ospf import OSPF
from tqdm import tqdm
import csv
import time

def analyze_ip_headers_chunked(pcap_file):
    start_time = time.time()
    output_csv="packet_analysis_chunked.csv"
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = [
            "Packet Number", "Source MAC", "Destination MAC", "EtherType",   # Eather layer 
            "IP Version", "Source IP", "Destination IP", "Header Length (bytes)",  # IPv4
            "Total Length (bytes)", "TTL", "Protocol", "Checksum","Flags", "Fragment Offset", "Identification",

            "Traffic Class", "Flow Label", "Payload Length (bytes)","Next Header", "Hop Limit",    # IPV6
            "Source Port", "Destination Port","Sequence Number", "Acknowledgment Number", "TCP Flags", # TCP
            "Window Size", "TCP Checksum", "Urgent Pointer", 
            "UDP Length", "UDP Checksum",  # UDP
            "ICMP Type", "ICMP Code", "ICMP ID", "ICMP Sequence",   # ICMP
            "ICMPv6 Type", "ICMPv6 Code", "ICMPv6 Checksum",   #ICMP v6
            "VLAN ID", "VLAN Priority",   #VLAN
            "MPLS Label", "MPLS TTL",   #MPLS
            "PPPoE Session ID", "PPPoE Length",   #PPPoE
            "OSPF Type", "OSPF Router ID", "OSPF Area ID"      #OSPF
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        with PcapReader(pcap_file) as reader, tqdm(desc="Reading packets", unit="pkt") as progress:
            for i, packet in enumerate(reader):
                packet_info = {"Packet Number": i + 1}

                if Ether in packet:
                    ether_layer = packet[Ether]
                    packet_info["Source MAC"] = ether_layer.src
                    packet_info["Destination MAC"] = ether_layer.dst
                    packet_info["EtherType"] = hex(ether_layer.type)

                if Dot1Q in packet:
                    vlan_layer = packet[Dot1Q]
                    packet_info["VLAN ID"] = vlan_layer.vlan
                    packet_info["VLAN Priority"] = vlan_layer.prio

                if MPLS in packet:
                    mpls_layer = packet[MPLS]
                    packet_info["MPLS Label"] = mpls_layer.label
                    packet_info["MPLS TTL"] = mpls_layer.ttl

                if PPPoE in packet:
                    pppoe_layer = packet[PPPoE]
                    packet_info["PPPoE Session ID"] = pppoe_layer.sessionid
                    packet_info["PPPoE Length"] = pppoe_layer.len

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

                    if ICMPv6ND_NS in packet:
                        icmpv6_ns = packet[ICMPv6ND_NS]
                        packet_info["ICMP Type"] = "Neighbor Solicitation"
                        packet_info["ICMP Code"] = icmpv6_ns.code

                    if ICMPv6ND_NA in packet:
                        icmpv6_na = packet[ICMPv6ND_NA]
                        packet_info["ICMP Type"] = "Neighbor Advertisement"
                        packet_info["ICMP Code"] = icmpv6_na.code

                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_info["Source Port"] = tcp_layer.sport
                    packet_info["Destination Port"] = tcp_layer.dport
                    packet_info["Sequence Number"] = tcp_layer.seq
                    packet_info["Acknowledgment Number"] = tcp_layer.ack
                    packet_info["TCP Flags"] = str(tcp_layer.flags)
                    packet_info["Window Size"] = tcp_layer.window
                    packet_info["TCP Checksum"] = tcp_layer.chksum
                    packet_info["Urgent Pointer"] = tcp_layer.urgptr

                if UDP in packet:
                    udp_layer = packet[UDP]
                    packet_info["Source Port"] = udp_layer.sport
                    packet_info["Destination Port"] = udp_layer.dport
                    packet_info["UDP Length"] = udp_layer.len
                    packet_info["UDP Checksum"] = udp_layer.chksum

                if ICMP in packet:
                    icmp_layer = packet[ICMP]
                    packet_info["ICMP Type"] = icmp_layer.type
                    packet_info["ICMP Code"] = icmp_layer.code
                    packet_info["Checksum"] = icmp_layer.chksum
                    packet_info["ICMP ID"] = icmp_layer.id
                    packet_info["ICMP Sequence"] = icmp_layer.seq

               

                if OSPF in packet:
                    ospf_layer = packet[OSPF]
                    packet_info["OSPF Type"] = ospf_layer.type
                    packet_info["OSPF Router ID"] = ospf_layer.routerid
                    packet_info["OSPF Area ID"] = ospf_layer.areaid

                writer.writerow(packet_info)
                progress.update(1)

        print("Packet reading finished")

    print(f"Data written directly to {output_csv}. Total time spent: {time.time() - start_time} seconds")


if __name__ == "__main__":
    pcap_file = "router-1.pcap" 
    analyze_ip_headers_chunked(pcap_file)
