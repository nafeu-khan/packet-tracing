import plt
from plt_testing import *


class Connection:
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.syn = False
        self.syn_ack = False
        self.ack = False
        self.fin = False
        self.fin_ack = False
        self.termination_ack = False
        self.data_transferred = 0  
        self.packet_count = 0
        self.connection_history = [] 
    
    def handle_syn(self):
        self.syn = True
    
    def handle_syn_ack(self):
        if self.syn:
            self.syn_ack = True
    
    def handle_ack(self):
        if self.syn_ack:
            self.ack = True
    
    def add_data(self, data_size):
        if self.ack:
            self.data_transferred += data_size
            self.packet_count += 1
    
    def handle_fin(self):
        if self.ack:
            self.fin = True

    def handle_fin_ack(self):
        if self.fin:
            self.fin_ack = True
    
    def handle_termination_ack(self):
        if self.fin_ack:
            self.termination_ack = True
            self.store_connection()
            self.reset_connection()
    
    def store_connection(self):
        connection_info = {
            'data_transferred': self.data_transferred,
            'packet_count': self.packet_count,
            'status': 'Terminated'
        }
        self.connection_history.append(connection_info)
    
    def reset_connection(self):
        self.syn = self.syn_ack = self.ack = False
        self.fin = self.fin_ack = self.termination_ack = False
        self.data_transferred = 0
        self.packet_count = 0
    
    def connection_established(self):
        return self.ack
    
    def connection_terminated(self):
        return self.termination_ack
    
    def __str__(self):
        connection_info = f"Connection {self.src_ip} -> {self.dst_ip}, Established: {self.connection_established()}, Terminated: {self.connection_terminated()}, Data: {self.data_transferred} bytes, Packets: {self.packet_count}"
        return connection_info

# t = get_example_trace(sys.argv[1])
t = get_example_trace('git_trace.pcap')
n=1

flags={
    1:"FIN",
    2:"Syn",
    4: "RST",
    8: "PSH",
    16: "ACK",
    17:"FIN+ACK",
    18:"SYN+ACK",
    24: "PSH+ACK",
    32: "URG"
}
for pkt in t:
    if pkt.tcp:
        # print_ip(pkt.ip,12)
        ip =pkt.ip
        tcp= pkt.tcp
        con_pair =(str(ip.src_prefix),(ip.dst_prefix), tcp.src_port, tcp.dst_port)
        flag="NO Flag found"
        if tcp.flags:
            flag=flags.get(tcp.flags,"No flag found")
            print(ip.src_prefix , " ->> " ,ip.dst_prefix, "flag ->",flag,"len ",tcp.pkt_len," flag-> ", tcp.flags)
        n+=1
        # if (n>21):
        #     break
print(n)