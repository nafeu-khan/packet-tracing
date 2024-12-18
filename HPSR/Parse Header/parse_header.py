from scapy.all import IP, IPv6, TCP, UDP, ICMP, SCTP, PcapReader
from tqdm import tqdm
import csv
import os
import time
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Parse PCAP files and generate header and port analysis results."
    )
    parser.add_argument("-y","--year", type=int, required=True, help="Year of the data (e.g., 2024).")
    parser.add_argument("-m","--month", type=int, required=True, help="Month of the data (1-12).")
    parser.add_argument("-f","--file", type=str, required=True, help="PCAP file to analyze.")
    return parser.parse_args()

def analyze_selected_headers(pcap_file, output_base_dir):
    start_time = time.time()

    # Define all CSV configurations with their fieldnames
    csv_configs = {
        "ip.csv": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                   "IHL(byte)", "DSCP", "ECN", "Protocol", "Packet Length"],
        "ip_tcp.csv": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                       "IHL(byte)", "DSCP", "ECN", "Protocol", "Packet Length", 
                       "TCP-Reserved", "TCP-CWR", "TCP-ECE", "TCP-Timestamp_Value"],
        "ip_udp.csv": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                       "IHL(byte)", "DSCP", "ECN", "Protocol", "Packet Length", "UDP_Length"],
        "ip_icmp.csv": ["Packet Number", "Source IP", "Destination IP", "Protocol", "Packet Length", "ICMP_Type"],
        "ip_sctp.csv": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                        "SCTP-Verification_Tag", "SCTP-Checksum"],
        "ipv6.csv": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                     "Flow Label", "Traffic Class", "Next Header", "Packet Length"],
        "ipv6_tcp.csv": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                         "Flow Label", "Traffic Class", "Next Header", "Packet Length", 
                         "TCP-Reserved", "TCP-CWR", "TCP-ECE", "TCP-Timestamp_Value"],
        "ipv6_udp.csv": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                         "Flow Label", "Traffic Class", "Next Header", "Packet Length", "UDP_Length"],
        "ipv6_icmp.csv": ["Packet Number", "Source IP", "Destination IP", "Next Header", "Packet Length", "ICMP_Type"],
        "ipv6_sctp.csv": ["Packet Number", "Source IP", "Destination IP", "Source Port", "Destination Port",
                          "Flow Label", "Traffic Class", "Next Header", "Packet Length", 
                          "SCTP-Verification_Tag", "SCTP-Checksum"]
    }

    # Initialize data buffers
    data_buffers = {key: [] for key in csv_configs.keys()}
    tcp_80_count = set()
    tcp_443_count = set()
    udp_443_count = set()

    # Create the output directory
    os.makedirs(output_base_dir, exist_ok=True)

    try:
        with PcapReader(pcap_file) as reader:
            progress = tqdm(desc="Reading packets", unit="pkt")

            for i, packet in enumerate(reader, start=1):
                packet_number = i


                #header count collection 
                # if IP in packet or IPv6 in packet:
                #     src_ip = packet[IP].src if IP in packet else packet[IPv6].src
                #     dst_ip = packet[IP].dst if IP in packet else packet[IPv6].dst

                #     if TCP in packet:
                #         sport = packet[TCP].sport
                #         dport = packet[TCP].dport

                #         if dport == 80 or sport == 80:  # HTTP (TCP 80)
                #             tcp_80_count.add((src_ip, sport, dst_ip, dport))

                #         if dport == 443 or sport == 443:  # HTTPS (TCP 443)
                #             tcp_443_count.add((src_ip, sport, dst_ip, dport))

                #     elif UDP in packet:
                #         sport = packet[UDP].sport
                #         dport = packet[UDP].dport

                #         if dport == 443 or sport == 443:  # UDP 443
                #             udp_443_count.add((src_ip, sport, dst_ip, dport))
                # # header count collection end
                src_port = "-"
                dst_port = "-"

                if packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(SCTP):
                    transport_layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP] if packet.haslayer(UDP) else packet[SCTP]
                    src_port = transport_layer.sport
                    dst_port = transport_layer.dport

                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    ip_layer = packet[IP]
                    base_data = {
                        "Packet Number": packet_number,
                        "Source IP": ip_layer.src,
                        "Destination IP": ip_layer.dst,
                        "Source Port": src_port,
                        "Destination Port": dst_port,
                        "IHL(byte)": ip_layer.ihl * 4,
                        "DSCP": ip_layer.tos >> 2,
                        "ECN": ip_layer.tos & 3,
                        "Protocol": ip_layer.proto,
                        "Packet Length": f"{ip_layer.len}" # header len only -> {len(ip_layer)}+
                    }
                    data_buffers["ip.csv"].append(base_data)

                    if packet.haslayer(TCP):
                        
                        sport = packet[TCP].sport
                        dport = packet[TCP].dport
                        if dport == 80 or sport == 80:  # HTTP (TCP 80)
                            tcp_80_count.add((src_ip, sport, dst_ip, dport))
                        if dport == 443 or sport == 443:  # HTTPS (TCP 443)
                            tcp_443_count.add((src_ip, sport, dst_ip, dport))

                        tcp_layer = packet[TCP]
                        tcp_data = base_data.copy()
                        tcp_data.update({
                            "TCP-Reserved": tcp_layer.reserved,
                            "TCP-CWR": bool(tcp_layer.flags & 0x80),
                            "TCP-ECE": bool(tcp_layer.flags & 0x40),
                            "TCP-Timestamp_Value": next((f"{opt[1][0]}, {opt[1][1]}" for opt in tcp_layer.options if opt[0] == 'Timestamp'), "-")
                        })
                        data_buffers["ip_tcp.csv"].append(tcp_data)

                    elif packet.haslayer(UDP):

                        sport = packet[UDP].sport
                        dport = packet[UDP].dport
                        if dport == 443 or sport == 443:  # UDP 443
                            udp_443_count.add((src_ip, sport, dst_ip, dport))

                        udp_layer = packet[UDP]
                        udp_data = base_data.copy()
                        udp_data["UDP_Length"] = f"{udp_layer.len}+{len(udp_layer)}" # header len only -> {len(udp_layer)}+ only paylaod len -> {udp_layer.plen}
                        data_buffers["ip_udp.csv"].append(udp_data)

                    elif  packet.haslayer(ICMP):
                        icmp_layer = packet[ICMP]
                        icmp_data = base_data.copy()
                        icmp_data["ICMP_Type"] = icmp_layer.type
                        data_buffers["ip_icmp.csv"].append(icmp_data)
                    elif  packet.haslayer(SCTP):
                        sctp_layer = packet[SCTP]
                        sctp_data = base_data.copy()
                        sctp_data.update({
                            "SCTP-Verification_Tag": sctp_layer.tag,
                            "SCTP-Checksum": sctp_layer.cksum
                        })
                        data_buffers["ip_sctp.csv"].append(sctp_data)

                elif  packet.haslayer(IPv6):
                    ipv6_layer = packet[IPv6]
                    src_ip = packet[IPv6].src
                    dst_ip = packet[IPv6].dst

                    base_data = {
                        "Packet Number": packet_number,
                        "Source IP": ipv6_layer.src,
                        "Destination IP": ipv6_layer.dst,
                        "Source Port": src_port,
                        "Destination Port": dst_port,
                        "Flow Label": ipv6_layer.fl,
                        "Traffic Class": ipv6_layer.tc,
                        "Next Header": ipv6_layer.nh,
                        "Packet Length": f"{len(ipv6_layer)}+{ipv6_layer.plen}" # header len only -> {len(ipv6_layer)}+ only paylaod len -> {ipv6_layer.plen}
                    }

                    # Add to IPv6 base CSV
                    data_buffers["ipv6.csv"].append(base_data)

                    if packet.haslayer(TCP):
                        
                        sport = packet[TCP].sport
                        dport = packet[TCP].dport
                        if dport == 80 or sport == 80:  # HTTP (TCP 80)
                            tcp_80_count.add((src_ip, sport, dst_ip, dport))
                        if dport == 443 or sport == 443:  # HTTPS (TCP 443)
                            tcp_443_count.add((src_ip, sport, dst_ip, dport))

                        tcp_layer = packet[TCP]
                        tcp_data = base_data.copy()
                        tcp_data.update({
                            "TCP-Reserved": tcp_layer.reserved,
                            "TCP-CWR": bool(tcp_layer.flags & 0x80),
                            "TCP-ECE": bool(tcp_layer.flags & 0x40),
                            "TCP-Timestamp_Value": next((f"{opt[1][0]}, {opt[1][1]}" for opt in tcp_layer.options if opt[0] == 'Timestamp'), "-")
                        })
                        data_buffers["ipv6_tcp.csv"].append(tcp_data)

                    elif packet.haslayer(UDP):
                        sport = packet[UDP].sport
                        dport = packet[UDP].dport

                        if dport == 443 or sport == 443:  # UDP 443
                            udp_443_count.add((src_ip, sport, dst_ip, dport))
                        
                        udp_layer = packet[UDP]
                        udp_data = base_data.copy()
                        udp_data["UDP_Length"] = f"{udp_layer.len}+{len(udp_layer)}" # header len only -> {len(udp_layer)}+ only paylaod len -> {udp_layer.plen}
                        data_buffers["ipv6_udp.csv"].append(udp_data)

                    elif  packet.haslayer(ICMP):
                        icmp_layer = packet[ICMP]
                        icmp_data = base_data.copy()
                        icmp_data["ICMP_Type"] = icmp_layer.type
                        data_buffers["ipv6_icmp.csv"].append(icmp_data)

                    elif packet.haslayer(SCTP):
                        sctp_layer = packet[SCTP]
                        sctp_data = base_data.copy()
                        sctp_data.update({
                            "SCTP-Verification_Tag": sctp_layer.tag,
                            "SCTP-Checksum": sctp_layer.cksum
                        })
                        data_buffers["ipv6_sctp.csv"].append(sctp_data)

                progress.update(1)

            progress.close()


        #for header_count_file start -------------
        connections_file = os.path.join(output_base_dir, "port_analysis_results.csv")
        count_header_file_path = os.path.join(output_base_dir, "count_header_file.csv")

        with open(count_header_file_path, 'w',  newline='') as countcsvfile:
            fieldnames = ["tcp_80_count", "tcp_443_count", "udp_443_count"]
            writer= csv.DictWriter(countcsvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow({
                "tcp_80_count": len(tcp_80_count),
                "tcp_443_count": len(tcp_443_count),
                "udp_443_count": len(udp_443_count)
            })

        with open(connections_file, 'w', newline='') as csvfile:
            fieldnames = ["tcp_80_connections", "tcp_443_connections", "udp_443_connections"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Find max rows based on the largest connection set
            max_rows = max(len(tcp_80_count), len(tcp_443_count), len(udp_443_count))

            tcp_80_list = list(tcp_80_count)
            tcp_443_list = list(tcp_443_count)
            udp_443_list = list(udp_443_count)

            for i in range(max_rows):
                writer.writerow({
                    "tcp_80_connections": tcp_80_list[i] if i < len(tcp_80_list) else "",
                    "tcp_443_connections": tcp_443_list[i] if i < len(tcp_443_list) else "",
                    "udp_443_connections": udp_443_list[i] if i < len(udp_443_list) else ""
                })
        # header count file write end ----------

        # Write all headers to their respective files
        for filename, rows in data_buffers.items():
            filepath = os.path.join(output_base_dir, filename)
            with open(filepath, 'w', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=csv_configs[filename])
                writer.writeheader()
                writer.writerows([{key: row.get(key, "") for key in csv_configs[filename]} for row in rows])

        print(f"Analysis completed in {time.time() - start_time:.2f} seconds.")
        print(f"Results saved to {output_base_dir}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    args = parse_arguments()

    # Generate output directory path based on year, month, and day
    year = args.year
    month = f"{args.month:02d}"
    day = args.file[6:8]  # Extract day from filename (e.g., "202403041400.pcap" -> day = "04")
    output_base_dir = os.path.join(f"{year}", f"{month}", day)

    print(f"Analyzing file: {args.file}")
    print(f"Saving results to: {output_base_dir}")
    analyze_selected_headers(args.file, output_base_dir)
