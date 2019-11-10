#import Packet
from struct import unpack
import socket
from Headers import EthernetHeader, IPv4Header, ARPHeader
from helpers import *
from Packet import Packet

class PacketParser():
    def __init__(self):
        pass

    def parse(self, raw_data):
        eth_headers, eth_data = self.parse_Ethernet(raw_data)
        network_header, network_data = self.parse_network_level(eth_data, str(eth_headers.etherType))
        packet = Packet(eth_headers, eth_headers.etherType, network_header, network_header.protocol_type, None, network_data)
        return packet
    
    def parse_network_level(self, eth_data, eth_type):
        if eth_type == "IPv4":
            return self.parse_IPv4(eth_data)
        elif eth_type == "ARP":
            return self.parse_ARP(eth_data)
        else:
            return "unknown", "unknown"
    
    def parse_Ethernet(self, raw_data):
        eth_length = 14

        destination_mac = raw_data[0:6]
        source_mac = raw_data[6:12]

        eth_header = raw_data[:eth_length]
        proto = eth_header[-2:]

        headers = EthernetHeader(destination_mac, source_mac, proto)
        return headers, raw_data[eth_length:]
    
    def parse_IPv4(self, eth_data):

        iph = unpack('!BBHHHBBH4s4s' , eth_data[0:20])
 
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
        s_addr = iph[8]
        d_addr = iph[9]

        if iph_length == 20:
            opt = None
        elif iph_length > 20:
            opt = eth_data[20:iph_length]
        else:
            print('parsing ip header error')
            pass
 
        header = IPv4Header(version, iph_length, type_of_service, total_len, datagram_id, flags, fr_offset, ttl, protocol, h_checksum, s_addr, d_addr, opt)

        return header, eth_data[header.header_length:]

    def parse_ARP(self, eth_data):
        first_part = unpack("!HHBBH", eth_data[:8])
        hw_type = int.to_bytes(first_part[0], byteorder='big', length=2)
        proto_type = int.to_bytes(first_part[1], byteorder='big', length=2)

        hw_adr_size = first_part[2]
        proto_addr_size = first_part[3]

        addrs_size = hw_adr_size+proto_addr_size

        opt = first_part[4]

        #addrs_format_expr = "{}s{}s".format(hw_adr_size, proto_addr_size)

        #hw_sender, proto_sender = unpack(addrs_format_expr, eth_data[8:8+addrs_size])
        #hw_target, proto_target = unpack(addrs_format_expr, eth_data[8+addrs_size:8+2*addrs_size])

        second_part = eth_data[8:8+addrs_size]

        hw_sender = second_part[:hw_adr_size]
        proto_sender = second_part[hw_adr_size:]

        third_part = eth_data[8+addrs_size:8+2*addrs_size]
        hw_target = third_part[:hw_adr_size]
        proto_target = third_part[hw_adr_size:]

        header = ARPHeader(hw_type, proto_type, hw_adr_size, proto_addr_size, opt, hw_sender, proto_sender, hw_target, proto_target)
        return header, b""

    def parse_tcp(self, raw_data):
        pass

    def parse_udp(self, raw_data):
        pass

    def parse_icmp(self, raw_data):
        pass
    
    
