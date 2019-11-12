from PacketParser import PacketParser

class TestParserTCP():
    with open('test_packets/tcp_packet', 'rb') as f:
        raw_data = f.read()
    parser = PacketParser()

    def test_mac_parsing(self):    
        header, data = self.parser.parse_Ethernet(self.raw_data)
        assert header.destination_MAC_address.to_string() == "00:50:56:e9:04:2e"
        assert header.source_MAC_address.to_string() == "00:0c:29:84:86:5f"
    
    def test_ip_address_parsing(self):
        eth_header, eth_data = self.parser.parse_Ethernet(self.raw_data)
        ip_header, data = self.parser.parse_IPv4(eth_data)
        assert ip_header.source_address.to_string() == "192.168.221.128"
        assert ip_header.destination_address.to_string() == "122.249.180.9"

class TestParserARP():
    with open('test_packets/arp_packet', 'rb') as f:
        raw_data = f.read()
    parser = PacketParser()

    def test_all(self):    
        h, data = self.parser.parse_Ethernet(self.raw_data)
        assert str(h.ether_type) == "ARP"
        arp_header = self.parser.parse_ARP(data)[0]
        assert str(arp_header.hardware_type) == "Ethernet"
        assert str(arp_header.protocol_type) == "IPv4"
        assert int(arp_header.hw_addr_byte_len) == 6
        assert int(arp_header.proto_addr_byte_len) == 4
        assert int(arp_header.operation_code) == 1
        assert str(arp_header.hw_addr_sender) == "b4:86:55:8c:fa:76"
        assert str(arp_header.proto_addr_sender) == "192.168.8.1"
        assert str(arp_header.hw_addr_target) == "00:00:00:00:00:00"
        assert str(arp_header.proto_addr_target) == "192.168.8.103"
    
    def test_all_2(self):
        self.parser.parse(self.raw_data)

class TestICMPParser():
    with open('test_packets/icmp_packet', 'rb') as f:
        raw_data = f.read()
    parser = PacketParser()

    def test_all(self):    
        h, data = self.parser.parse_Ethernet(self.raw_data)
        assert str(h.ether_type) == "IPv4"
        ip_header, ip_data = self.parser.parse_IPv4(data)
        assert str(ip_header.protocol_type) == "ICMP"
        icmp_h, data = self.parser.parse_icmp(ip_data)
        assert str(icmp_h.type) == "Echo Request"


class TestDHCPParser():
    with open('test_packets/dhcp_packet', 'rb') as f:
        raw_data = f.read()
    parser = PacketParser()

    def test_all(self):
        pass


class TestUDPParser():
    with open('test_packets/udp_packet', 'rb') as f:
        raw_data = f.read()
    parser = PacketParser()

    def test_all(self):    
        h, data = self.parser.parse_Ethernet(self.raw_data)
        assert str(h.ether_type) == "IPv4"
        ip_header, ip_data = self.parser.parse_IPv4(data)
        assert str(ip_header.protocol_type) == "UDP"
        udp_h, data = self.parser.parse_udp(ip_data)
        assert udp_h.source_port == 50178
        assert udp_h.destination_port == 3702
        assert udp_h.length == 999