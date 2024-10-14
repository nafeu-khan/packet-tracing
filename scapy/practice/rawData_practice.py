from scapy.all import rdpcap, IP, TCP, Raw,IPv6, TCP, UDP


def raw_data(packets):
    for i, packet in enumerate(packets):
        print(f"--- Packet {i+1} ---")
        print(packet)
        print('-------------------')
        if (i>5):
            break
        if IP in packet:
            ip_layer = packet[IP]
            print(f"Source IP: {ip_layer.src}, Dest. IP: {ip_layer.dst}")
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}, Dest. Port: {tcp_layer.dport} Flags: {tcp_layer.flags}")
            #flag S A F U R P E C   
        total_packet_size = len(packet)
        payload_size=header_size=0
        # total header size 
          # network layer
        if IP in packet:
            header_size += len(packet[IP])  
        elif IPv6 in packet:
            header_size += len(packet[IPv6]) 
            # transport layer
        if TCP in packet:
            header_size += len(packet[TCP]) 
        elif UDP in packet:
            header_size += len(packet[UDP])
        if Raw in packet:
            data_payload = packet[Raw].load
            payload_size= len(packet[Raw].load)
            print(f"Data Payload: {data_payload} , payload size: {payload_size} bytes")
        print(f"Header size {header_size}, Total size {header_size+payload_size}, "
        )
        print("=====================")
if __name__== '__main__':
    file_path = 'router-1.pcap' 
    packets = rdpcap(file_path)
    raw_data(packets) 