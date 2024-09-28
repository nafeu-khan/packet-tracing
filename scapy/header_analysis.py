from scapy.all import rdpcap, IP, IPv6

def analyze_ip_headers(pcap_file):
    packets = rdpcap(pcap_file)

    for i, packet in enumerate(packets):
        print(f"--- Packet {i+1} ---")
        if (i >6):
            break
        if IP in packet:
            ip_layer = packet[IP]
            print("IPv4 Header:")
            print(f"  Source IP: {ip_layer.src}")
            print(f"  Destination IP: {ip_layer.dst}")
            print(f"  Version: {ip_layer.version}")
            print(f"  Header Length: {ip_layer.ihl * 4} bytes")
            print(f"  Total Length: {ip_layer.len} bytes")
            print(f"  TTL: {ip_layer.ttl}")
            print(f"  Protocol: {ip_layer.proto}")
            print(f"  Checksum: {ip_layer.chksum}")
            print(f"  Flags: {ip_layer.flags}")
            print(f"  Fragment Offset: {ip_layer.frag}")
            print(f"  Time to Live: {ip_layer.ttl}")
            print(f"  Identification: {ip_layer.id}")
        else :
            print("Packet does not contain either IPv4 layer.")
        if IPv6 in packet:
            ipv6_layer = packet[IPv6]
            print("IPv6 Header:")
            print(f"  Source IP: {ipv6_layer.src}")
            print(f"  Destination IP: {ipv6_layer.dst}")
            print(f"  Version: {ipv6_layer.version}")
            print(f"  Traffic Class: {ipv6_layer.tc}")
            print(f"  Flow Label: {ipv6_layer.fl}")
            print(f"  Payload Length: {ipv6_layer.plen} bytes")
            print(f"  Next Header: {ipv6_layer.nh}")
            print(f"  Hop Limit: {ipv6_layer.hlim}")

        else:
            print("Packet does not contain IPv6 layer.")

if __name__ == "__main__":
    pcap_file = 'router-1.pcap'
    analyze_ip_headers(pcap_file)
