from PacketParser import PacketParser

class TestParserTCP():
    raw_data = bytes.fromhex("005056e9042e000c2984865f0800450000341ffc400080060000c0a8dd807af9b4090501c8d53a684fdb0000000080022000cd520000020405b40103030801010402")
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
    raw_data = bytes.fromhex("9cb70d835732b486558cfa7608060001080006040001b486558cfa76c0a80801000000000000c0a80867")
    parser = PacketParser()

    def test_all(self):    
        h, data = self.parser.parse_Ethernet(self.raw_data)
        assert str(h.etherType) == "ARP"
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



