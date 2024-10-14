from scapy.all import IP, IPv6, Ether, TCP, UDP, ICMP, Dot1Q, PPPoE, PcapReader

from tqdm import tqdm
import csv
import time

def analyze_selected_headers(pcap_file):
    start_time = time.time()
    output_csv = "selected_header_analysis.csv"
    
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = [
            "Packet Number","Source IP","Destination IP", "IHL(byte)", "DSCP", "ECN", "Protocol", 
            "Flow Label", "Traffic Class", "Next Header",
            "TCP RSV", "TCP CWR", "TCP ECE", 
            "UDP Length", 
            "ICMP Type" 
        ]
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        with PcapReader(pcap_file) as reader, tqdm(desc="Reading packets", unit="pkt") as progress:
            for i, packet in enumerate(reader):
                packet_info = {"Packet Number": i + 1}
                
                if IP in packet:
                    ip_layer = packet[IP]
                    packet_info["Source IP"] = ip_layer.src
                    packet_info["Destination IP"] = ip_layer.dst
                    packet_info["IHL(byte)"] = ip_layer.ihl * 4 #in byte
                    packet_info["DSCP"] = ip_layer.tos >> 2 # if ip_layer.tos >> 2 != 0 else None 
                    packet_info["ECN"] = ip_layer.tos & 3 # if ip_layer.tos & 3 != 0 else None  
                    packet_info["Protocol"] = ip_layer.proto
                
                if IPv6 in packet:
                    ipv6_layer = packet[IPv6]
                    packet_info["Source IP"] = ipv6_layer.src
                    packet_info["Destination IP"] = ipv6_layer.dst
                    packet_info["Flow Label"] = ipv6_layer.fl #if ipv6_layer.fl != 0 else None  
                    packet_info["Traffic Class"] = ipv6_layer.tc #if ipv6_layer.tc != 0 else None 
                    packet_info["Next Header"] = ipv6_layer.nh
                
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    if tcp_layer.reserved: packet_info["TCP RSV"] = (tcp_layer.reserved) 
                    packet_info["TCP CWR"] = bool(tcp_layer.flags & 0x80)  # 8th bit
                    packet_info["TCP ECE"] = bool(tcp_layer.flags & 0x40) #7thbit
                
                if UDP in packet:
                    udp_layer = packet[UDP]
                    packet_info["UDP Length"] = udp_layer.len 
                
                if ICMP in packet:
                    icmp_layer = packet[ICMP]
                    packet_info["ICMP Type"] = icmp_layer.type 
                
                if any(value is not None for key, value in packet_info.items() if key != "Packet Number"):
                    writer.writerow(packet_info)
                
                progress.update(1)
                # print(i," ...")
        
        print("Packet reading finished.")
    print(f"Data written directly to {output_csv}. Total time spent: {time.time() - start_time} seconds")


if __name__ == "__main__":
    pcap_file = "200608241400.dump"
    analyze_selected_headers(pcap_file)
