import pyshark

def analysis_of_trace(cap, ip1, ip2):
    previous_time = None
    packet_count = 0
    total_data_size = 0
    data_sent={}
    time_gaps = []
    # print(cap)
    for i,packet in enumerate(cap):
        # print(packet) #ethernet , ip,tcp
        # return
        if 'IP' in packet and ((packet.ip.src == ip1 and packet.ip.dst == ip2) or (packet.ip.src == ip2 and packet.ip.dst == ip1)):
            packet_count += 1

            packet_time = float(packet.sniff_timestamp)
            packet_length = int(packet.length)
            total_data_size += packet_length
            key=f'{packet.ip.src} -> {packet.ip.dst}'
            if key in data_sent: data_sent[key] += packet_length
            else :data_sent[key] = packet_length
            if previous_time is not None:
                time_gap = float((packet_time - previous_time))/1000.00
                # time_gap = round((packet_time - previous_time) / 1000, 5)

                time_gaps.append((time_gap,i))
            else:
                time_gaps.append((0,i)) 

            previous_time = packet_time

    cap.close()
    for gap in time_gaps:
        print(f"time between {gap[1]} and {gap[1]-1} packets is : {gap[0]:.8f} milisecond")
    
    print("============")
    for key,value in data_sent.items():
        print(f' For {key} => sent data: {value} bytes')
    print('=============')
    print(f"Connection between {ip1} and {ip2}:")
    print(f"Total Packets: {packet_count}")
    print(f"Total Data Size: {total_data_size} bytes")
    time_gap_list= [gap[0] for gap in time_gaps]
    average_time = sum(time_gap_list) / len(time_gap_list)
    print(f"Average Time Gap: {average_time:.8f} seconds (between consecutive packets)")

if __name__ == "__main__":
    file_path = 'router-1.pcap' 
    capture = pyshark.FileCapture(file_path)
    ip1 = '172.16.11.1'
    ip2 = '172.16.10.1' 

    analysis_of_trace(capture, ip1, ip2)
