from PacketParser import PacketParser


class TestParser():
    def test_mac_parsing(self):
        raw_data = bytes.fromhex("005056e9042e000c2984865f0800450000341ffc400080060000c0a8dd807af9b4090501c8d53a684fdb0000000080022000cd520000020405b40103030801010402")
        parser = PacketParser()
        headers, data = parser.parse_Ethernet(raw_data)
        assert headers.destination_MAC_address.string() == "00:50:56:e9:04:2e"
        assert headers.source_MAC_address.string() == "00:0c:29:84:86:5f"