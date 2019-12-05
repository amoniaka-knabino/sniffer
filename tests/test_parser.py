import PacketParser as pp
import unittest

class TestParserTCP(unittest.TestCase):
    with open('test_packets/tcp_packet', 'rb') as f:
        raw_data = f.read()
    parser = pp

    def test_mac_parsing(self):
        h, data = self.parser.parse_Ethernet(self.raw_data)
        self.assertEqual( str(h.destination_MAC_address) , "00:50:56:e9:04:2e")
        self.assertEqual( str(h.source_MAC_address) , "00:0c:29:84:86:5f")

    def test_ip_address_parsing(self):
        eth_header, eth_data = self.parser.parse_Ethernet(self.raw_data)
        ip_header, data = self.parser.parse_IPv4(eth_data)
        self.assertEqual( str(ip_header.source_address) , "192.168.221.128")
        self.assertEqual( str(ip_header.destination_address) , "122.249.180.9")


class TestParserARP(unittest.TestCase):
    with open('test_packets/arp_packet', 'rb') as f:
        raw_data = f.read()
    parser = pp

    def test_all(self):
        h, data = self.parser.parse_Ethernet(self.raw_data)
        self.assertEqual( str(h.ether_type) , "ARP")
        arp_header = self.parser.parse_ARP(data)[0]
        self.assertEqual( str(arp_header.hardware_type) , "Ethernet")
        self.assertEqual( str(arp_header.protocol_type) , "IPv4")
        self.assertEqual( int(arp_header.hw_addr_byte_len) , 6)
        self.assertEqual( int(arp_header.proto_addr_byte_len) , 4)
        self.assertEqual( int(arp_header.operation_code) , 1)
        self.assertEqual( str(arp_header.hw_addr_sender) , "b4:86:55:8c:fa:76")
        self.assertEqual( str(arp_header.proto_addr_sender) , "192.168.8.1")
        self.assertEqual( str(arp_header.hw_addr_target) , "00:00:00:00:00:00")
        self.assertEqual( str(arp_header.proto_addr_target) , "192.168.8.103")

    def test_all_2(self):
        self.parser.parse_all_packet(self.raw_data)


class TestICMPParser(unittest.TestCase):
    with open('test_packets/icmp_packet', 'rb') as f:
        raw_data = f.read()
    parser = pp

    def test_all(self):
        h, data = self.parser.parse_Ethernet(self.raw_data)
        self.assertEqual( str(h.ether_type) , "IPv4")
        ip_header, ip_data = self.parser.parse_IPv4(data)
        self.assertEqual( str(ip_header.protocol_type) , "ICMP")
        icmp_h, data = self.parser.parse_icmp(ip_data)
        self.assertEqual( str(icmp_h.type) , "Echo Request")


class TestUDPParser(unittest.TestCase):
    with open('test_packets/udp_packet', 'rb') as f:
        raw_data = f.read()
    parser = pp

    def test_all(self):
        h, data = self.parser.parse_Ethernet(self.raw_data)
        self.assertEqual( str(h.ether_type) , "IPv4")
        ip_header, ip_data = self.parser.parse_IPv4(data)
        self.assertEqual( str(ip_header.protocol_type) , "UDP")
        udp_h, data = self.parser.parse_udp(ip_data)
        self.assertEqual( udp_h.source_port , 50178)
        self.assertEqual( udp_h.destination_port , 3702)
        self.assertEqual( udp_h.length , 999)
