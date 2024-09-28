from scapy.all import IP, ICMP, Ether

# create ip packet
ip_packet = IP(dst="192.168.1.1")

# create ICMP packet
icmp_packet = ICMP()

#combine IP and ICMP to form a complete packet
complete_packet = ip_packet / icmp_packet

print(complete_packet.show())  #packet details
