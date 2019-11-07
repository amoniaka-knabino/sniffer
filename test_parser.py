from PacketParser import PacketParser

class TestParser():
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

