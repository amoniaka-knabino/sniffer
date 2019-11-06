#import Packet
from struct import unpack
import socket
from Headers import EthernetHeader
from helpers import *

class PacketParser():
    def __init__(self):
        pass

    def parse(self, raw_data):
        pass
        #packet = Packet.Packet()
    
    def parse_Ethernet(self, raw_data):
        eth_length = 14

        destination_mac = raw_data[0:6]
        source_mac = raw_data[6:12]

        eth_header = raw_data[:eth_length]
        print(eth_header)
        proto = eth_header[-2:]
        #crc = ...

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
    
    
