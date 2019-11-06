#import Packet
from struct import unpack
import socket
from Headers import EthernetHeader

class PacketParser():
    def __init__(self):
        pass

    def parse(self, raw_data):
        pass
        #packet = Packet.Packet()
    
    def eth_addr(self, a):
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0] , a[1] , a[2], a[3], a[4] , a[5])
        return b
    
    def parse_Ethernet(self, raw_data):
        eth_length = 14

        destination_mac = self.eth_addr(raw_data[0:6])
        source_mac = self.eth_addr(raw_data[6:12])

        eth_header = raw_data[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        proto = socket.ntohs(eth[2]) ### разобраться

        headers = EthernetHeader(destination_mac, source_mac, proto)
        return headers, raw_data[eth_length:]
    
    def parse_ip(self, raw_data):
        pass

    def parse_tcp(self, raw_data):
        pass

    def parse_udp(self, raw_data):
        pass

    def parse_icmp(self, raw_data):
        pass
    
    
