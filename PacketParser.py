from struct import unpack
import socket
import Headers
from Packet import Packet
from collections import defaultdict

PLUGINS = defaultdict(lambda: lambda raw_data: Packet(None, raw_data))


def register(func):
    """Register a function as a plug-in"""
    PLUGINS[func.__name__] = func
    return func


def parse_raw_packet(raw_data, protocol_type):
    pack = PLUGINS[f"parse_{protocol_type}"](raw_data)
    if type(pack.header) is Headers.IPv4Header:
        proto = str(pack.header.protocol_type)
    elif type(pack.header) is Headers.EthernetHeader:
        proto = str(pack.header.ether_type)
    else:
        return pack
    return Packet(pack.header, parse_raw_packet(pack.data, proto))


@register
def parse_Ethernet(raw_data):
    eth_length = 14
    destination_mac, source_mac, proto = divide_packet([6, 6, 2], raw_data)

    headers = Headers.EthernetHeader(destination_mac, source_mac, proto)
    #print(type(headers) is EthernetHeader)
    return Packet(headers, raw_data[eth_length:])


@register
def parse_IPv4(eth_data):

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

    header = Headers.IPv4Header(version, iph_length, type_of_service,
                                total_len, datagram_id, flags, fr_offset,
                                ttl, protocol, h_checksum, s_addr, d_addr, opt)
    #print(isinstance(header, NetworkHeader) )
    return Packet(header, eth_data[header.header_length:])


@register
def parse_ARP(eth_data):
    hw_type, proto_type, hw_adr_size, proto_addr_size, opt = divide_packet(
        [2, 2, 1, 1, 2], eth_data)

    hw_adr_size = unpack("!B", hw_adr_size)[0]
    proto_addr_size = unpack("!B", proto_addr_size)[0]

    addrs_size = hw_adr_size+proto_addr_size

    hw_sender, proto_sender = divide_packet(
        [hw_adr_size, proto_addr_size], eth_data, 8)
    hw_target, proto_target = divide_packet(
        [hw_adr_size, proto_addr_size], eth_data, 8+addrs_size)

    header = Headers.ARPHeader(hw_type, proto_type, hw_adr_size, proto_addr_size,
                               opt, hw_sender, proto_sender,
                               hw_target, proto_target)
    return Packet(header, b"")


@register
def parse_TCP(raw_data):
    """
    https://www.techrepublic.com/article/exploring-the-anatomy-of-a-data-packet/
    https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    """

    s_port, d_port, seq_num, ack_num = divide_packet([2, 2, 4, 4], raw_data)
    data_offset = raw_data[12] >> 4

    tcph_len = data_offset // 4
    # reserved
    NS = raw_data[12] & 1
    other_flags = raw_data[13]
    flags = bytes([NS]) + bytes([other_flags])

    opt = raw_data[20:tcph_len]

    window_size, check_sum, urgent_pointer = divide_packet(
        [2, 2, 2], raw_data, 14)

    return Packet(Headers.TCPHeader(s_port, d_port, seq_num, ack_num,
                                    data_offset, flags, window_size,
                                    check_sum, urgent_pointer, opt),
                  raw_data[tcph_len:])


@register
def parse_UDP(raw_data):
    s_port, d_port, length, checksum = divide_packet([2, 2, 2, 2], raw_data)
    return Packet(Headers.UDPHeader(s_port, d_port, length, checksum), raw_data[8:])


@register
def parse_ICMP(raw_data):
    icmp_type, code, checksum = divide_packet([1, 1, 2], raw_data)
    return Packet(Headers.ICMPHeader(icmp_type, code, checksum), raw_data[4:])


def divide_packet(sizes_list, pack_bytes, position=0):
    """
    analog struct.unpack()
    1: item format: { field_name : number_of_bytes } - isn't used
    2: item format = number_of_bytes_in_part - used now
    """
    divided_packet = []
    for i in sizes_list:
        divided_packet.append(pack_bytes[position:position+i])
        position += i
    return divided_packet
