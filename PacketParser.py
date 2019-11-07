#import Packet
from struct import unpack
import socket
from Headers import EthernetHeader, IPv4Headers
from helpers import *
from Packet import Packet

class PacketParser():
    def __init__(self):
        pass

    def parse(self, raw_data):
        #packet = Packet.Packet()
        eth_headers, eth_data = self.parse_Ethernet(raw_data)

        if eth_headers.etherType.int == 8:
            self.parse_IPv4(eth_data)
    
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
    
    def parse_IPv4(self, eth_data):
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = eth_data[0:20]
         
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
        version_ihl = iph[0]
        # version_ihl_byte = [ver(4 bits), ihl(4 bits)]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iph_length = ihl * 4 #???

        type_of_service = iph[1]
        total_len = iph[2] #should I change byteorder
        datagram_id = iph[3]
        
        flags_fr_offset = iph[4]
        flags = flags_fr_offset >> 13
        fr_offset = flags_fr_offset & 0xFF

        ttl = iph[5]
        protocol = iph[6]
        h_checksum = iph[7]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
 
        print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
        print('\n')
        headers = IPv4Headers(version, ihl, type_of_service, total_len, datagram_id, flags, fr_offset, ttl, protocol, h_checksum, s_addr, d_addr, None, None)
        print(headers.__dict__)
        print('\n\n')

    def parse_tcp(self, raw_data):
        pass

    def parse_udp(self, raw_data):
        pass

    def parse_icmp(self, raw_data):
        pass
    
    
