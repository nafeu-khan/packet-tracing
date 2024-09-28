from scapy.all import rdpcap, IP

def analysis_of_trace(pcap_file, ip1, ip2):
    packets = rdpcap(pcap_file)
    previous_time = None
    packet_count = 0
    total_data_size = 0
    data_sent = {}
    time_gaps = []

    for i, packet in enumerate(packets):
       
        if IP in packet and ((packet[IP].src == ip1 and packet[IP].dst == ip2) or (packet[IP].src == ip2 and packet[IP].dst == ip1)):
            packet_count += 1

            packet_time = float(packet.time)
            packet_length = len(packet)
            total_data_size += packet_length
            key = f'{packet[IP].src} -> {packet[IP].dst}'
            
            if key in data_sent:
                data_sent[key] += packet_length
            else:
                data_sent[key] = packet_length

            if previous_time is not None:
                time_gap = packet_time - previous_time
                time_gaps.append((time_gap, i))
            else:
                time_gaps.append((0, i))

            previous_time = packet_time
   
    for gap in time_gaps:
        print(f"Time between packet {gap[1]} and {gap[1]-1}: {gap[0]:.8f} seconds")
    
    print("============")
   
    for key, value in data_sent.items():
        print(f'For {key} => Sent data: {value} bytes')
    
    print('=============')
    print(f"Connection between {ip1} and {ip2}:")
    print(f"Total Packets: {packet_count}")
    print(f"Total Data Size: {total_data_size} bytes")
    
    time_gap_list = [gap[0] for gap in time_gaps]
    if time_gap_list:
        average_time = sum(time_gap_list) / len(time_gap_list)
        print(f"Average Time Gap: {average_time:.8f} seconds (between consecutive packets)")

if __name__ == "__main__":
    file_path = 'router-1.pcap' 
    ip1 = '172.16.11.1'
    ip2 = '172.16.10.1'

    analysis_of_trace(file_path, ip1, ip2)
