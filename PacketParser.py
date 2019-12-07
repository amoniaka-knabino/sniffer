from struct import unpack
import socket
from Headers import *
from helpers import *
from Packet import Packet

PLUGINS = dict()

def register(func):
    """Register a function as a plug-in"""
    PLUGINS[func.__name__] = func
    return func

def parse_raw_packet(raw_data, protocol_type):  
    pack = PLUGINS[f"parse_{protocol_type}"](raw_data)
    if type(pack.header) is IPv4Header:
        proto = str(pack.header.protocol_type)
    elif type(pack.header) is EthernetHeader:
        proto = str(pack.header.ether_type)
    else:
        proto = "unknown"
        return pack
    return Packet(pack.header, parse_raw_packet(pack.data, proto))


@register
def parse_Ethernet( raw_data):
    eth_length = 14

    destination_mac = raw_data[0:6]
    source_mac = raw_data[6:12]

    eth_header = raw_data[:eth_length]
    proto = eth_header[-2:]

    headers = EthernetHeader(destination_mac, source_mac, proto)
    #print(type(headers) is EthernetHeader)
    return Packet(headers, raw_data[eth_length:])

@register
def parse_IPv4( eth_data):

    iph = unpack('!BBHHHBBH4s4s', eth_data[0:20])

    version_ihl = iph[0]
    # version_ihl_byte = [ver(4 bits), ihl(4 bits)]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4  # ???

    type_of_service = iph[1]
    total_len = iph[2]  # should I change byteorder
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
        raise ValueError("Parse IP Header Error")

    header = IPv4Header(version, iph_length, type_of_service,
                        total_len, datagram_id, flags, fr_offset,
                        ttl, protocol, h_checksum, s_addr, d_addr, opt)
    #print(isinstance(header, NetworkHeader) )
    return Packet(header, eth_data[header.header_length:])

@register
def parse_ARP( eth_data):
    first_part = unpack("!HHBBH", eth_data[:8])
    hw_type = int.to_bytes(first_part[0], byteorder='big', length=2)
    proto_type = int.to_bytes(first_part[1], byteorder='big', length=2)

    hw_adr_size = first_part[2]
    proto_addr_size = first_part[3]

    addrs_size = hw_adr_size+proto_addr_size

    opt = first_part[4]

    second_part = eth_data[8:8+addrs_size]

    hw_sender = second_part[:hw_adr_size]
    proto_sender = second_part[hw_adr_size:]

    third_part = eth_data[8+addrs_size:8+2*addrs_size]
    hw_target = third_part[:hw_adr_size]
    proto_target = third_part[hw_adr_size:]

    header = ARPHeader(hw_type, proto_type, hw_adr_size, proto_addr_size,
                        opt, hw_sender, proto_sender,
                        hw_target, proto_target)
    return Packet(header, b"")

@register
def parse_TCP( raw_data):
    """
    https://www.techrepublic.com/article/exploring-the-anatomy-of-a-data-packet/
    https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    """
    s_port = raw_data[:2]
    d_port = raw_data[2:4]
    seq_num = raw_data[4:8]
    ack_num = raw_data[8:12]
    data_offset = raw_data[12] >> 4

    tcph_len = data_offset // 4
    # reserved
    NS = raw_data[12] & 1
    other_flags = raw_data[13]
    flags = bytes([NS]) + bytes([other_flags])

    window_size = raw_data[14:16]
    check_sum = raw_data[16:18]
    urgent_pointer = raw_data[18:20]

    opt = raw_data[20:tcph_len]

    return Packet(TCPHeader(s_port, d_port, seq_num, ack_num,
                        data_offset, flags, window_size,
                        check_sum, urgent_pointer, opt), raw_data[tcph_len:])

@register
def parse_UDP( raw_data):
    s_port = raw_data[:2]
    d_port = raw_data[2:4]
    length = raw_data[4:6]
    checksum = raw_data[6:8]
    return Packet(UDPHeader(s_port, d_port, length, checksum), raw_data[8:])

@register
def parse_ICMP( raw_data):
    header = unpack("BBH", raw_data[:4])
    icmp_type = header[0]
    code = header[1]
    checksum = header[2]
    return Packet(ICMPHeader(icmp_type, code, checksum), raw_data[4:])

@register
def parse_unknown(raw_data):
    return Packet(None, raw_data)
