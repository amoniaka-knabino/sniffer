import unittest
from pack_filter import OneArgumentSimpleFilter
import PacketParser as pp

class _FilterTest():
    raw_data = b''
    one_lvl_pack = None
    all_lvl_pack = None
    pack_filter = None


    def test_all_lvl_filter_with_one_lvl_pack(self):
        res = self.pack_filter.filter_all_levels(self.one_lvl_pack)
        self.assertTrue(res)
    
    def test_all_lvl_filter_with_all_lvl_pack(self):
        res = self.pack_filter.filter_all_levels(self.all_lvl_pack)
        self.assertTrue(res)
    
    def test_one_lvl_filter_with_all_lvl_pack(self):
        res = self.pack_filter.filter_one_level(self.all_lvl_pack)
        self.assertTrue(res)
    
    def test_one_lvl_filter_with_one_lvl_pack(self):
        res = self.pack_filter.filter_one_level(self.one_lvl_pack)
        self.assertTrue(res)

class TestFilterOnTCP(_FilterTest, unittest.TestCase):
    with open('test_packets/tcp_packet', 'rb') as f:
        raw_data = f.read()
    pack_filter = OneArgumentSimpleFilter("EthernetHeader.destination_MAC_address=="+"00:50:56:e9:04:2e")
    one_lvl_pack = pp.parse_Ethernet(raw_data)
    all_lvl_pack = pp.parse_raw_packet(raw_data, 'Ethernet')