from struct import unpack
import socket
from Headers import *
from helpers import *
from Packet import Packet


class PacketParser:

    def parse(self, raw_data):
        eth_headers, eth_data = self.parse_Ethernet(raw_data)
        network_header, network_data = self.parse_network_level(
            eth_data, str(eth_headers.ether_type))
        trasport_header, transport_data = self.parse_transport_level(
            network_data, str(network_header.protocol_type))
        packet = Packet(eth_headers, eth_headers.ether_type,
                        network_header, network_header.protocol_type,
                        trasport_header, transport_data)
        return packet

    def parse_transport_level(self, ip_data, protocol_type):
        if protocol_type == "ICMP":
            return self.parse_icmp(ip_data)
        elif protocol_type == "UDP":
            return self.parse_udp(ip_data)
        elif protocol_type == "TCP":
            return self.parse_tcp(ip_data)
        else:
            return None, ip_data

    def parse_network_level(self, eth_data, eth_type):
        if eth_type == "IPv4":
            return self.parse_IPv4(eth_data)
        elif eth_type == "ARP":
            return self.parse_ARP(eth_data)
        else:
            return None, eth_data

    def parse_Ethernet(self, raw_data):
        eth_length = 14

        destination_mac = raw_data[0:6]
        source_mac = raw_data[6:12]

        eth_header = raw_data[:eth_length]
        proto = eth_header[-2:]

        headers = EthernetHeader(destination_mac, source_mac, proto)
        return headers, raw_data[eth_length:]

    def parse_IPv4(self, eth_data):

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
            print('parsing ip header error')
            pass

        header = IPv4Header(version, iph_length, type_of_service,
                            total_len, datagram_id, flags, fr_offset,
                            ttl, protocol, h_checksum, s_addr, d_addr, opt)

        return header, eth_data[header.header_length:]

    def parse_ARP(self, eth_data):
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
        return header, b""

    def parse_tcp(self, raw_data):
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

        return TCPHeader(s_port, d_port, seq_num, ack_num,
                         data_offset, flags, window_size,
                         check_sum, urgent_pointer, opt), raw_data[tcph_len:]

    def parse_udp(self, raw_data):
        s_port = raw_data[:2]
        d_port = raw_data[2:4]
        length = raw_data[4:6]
        checksum = raw_data[6:8]
        return UDPHeader(s_port, d_port, length, checksum), raw_data[8:]

    def parse_icmp(self, raw_data):
        header = unpack("BBH", raw_data[:4])
        icmp_type = header[0]
        code = header[1]
        checksum = header[2]
        return ICMPHeader(icmp_type, code, checksum), raw_data[4:]
