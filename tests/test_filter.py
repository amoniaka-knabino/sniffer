import unittest
from pack_filter import OneArgumentSimpleFilter
import PacketParser as pp

class _FilterDefaultTest():
    raw_data = b''
    one_lvl_pack = None
    all_lvl_pack = None
    pack_filter = None
    
    def check(self, res):
        return self.assertTrue(res)

    def test_all_lvl_filter_with_one_lvl_pack(self):
        res = self.pack_filter.filter_all_levels(self.one_lvl_pack)
        self.check(res)
    
    def test_all_lvl_filter_with_all_lvl_pack(self):
        res = self.pack_filter.filter_all_levels(self.all_lvl_pack)
        self.check(res)
    
    def test_one_lvl_filter_with_one_lvl_pack(self):
        res = self.pack_filter.filter_one_level(self.one_lvl_pack)
        self.check(res)

class TestFilterMAC(_FilterDefaultTest, unittest.TestCase):
    with open('test_packets/tcp_packet', 'rb') as f:
        raw_data = f.read()
    pack_filter = OneArgumentSimpleFilter("EthernetHeader.destination_MAC_address=="+"00:50:56:e9:04:2e")
    one_lvl_pack = pp.parse_Ethernet(raw_data)
    all_lvl_pack = pp.parse_raw_packet(raw_data, 'Ethernet')

    def test_one_lvl_filter_with_all_lvl_pack(self):
        res = self.pack_filter.filter_one_level(self.all_lvl_pack)
        self.check(res)

class TestFilterMACWrong(TestFilterMAC):
    pack_filter = OneArgumentSimpleFilter("EthernetHeader.destination_MAC_address=="+"00:50:53:e9:04:2e")
    def check(self, res):
        return self.assertFalse(res)

class TestFilterIP(_FilterDefaultTest, unittest.TestCase):
    with open('test_packets/tcp_packet', 'rb') as f:
        raw_data = f.read()
    pack_filter = OneArgumentSimpleFilter('IPv4Header.source_address==192.168.221.128')
    all_lvl_pack = pp.parse_raw_packet(raw_data, 'Ethernet')
    one_lvl_pack = all_lvl_pack.data

class TestFilterIPWrong(TestFilterIP):
    pack_filter = OneArgumentSimpleFilter('IPv4Header.source_address==1.168.221.128')
    def check(self, res):
        return self.assertFalse(res)

class TestFilterPort(_FilterDefaultTest, unittest.TestCase):
    with open('test_packets/udp_packet', 'rb') as f:
        raw_data = f.read()
    pack_filter = OneArgumentSimpleFilter('UDPHeader.source_port==50178')
    all_lvl_pack = pp.parse_raw_packet(raw_data, 'Ethernet')
    one_lvl_pack = all_lvl_pack.data.data

class TestFilterPortWrong(TestFilterPort):
    pack_filter = OneArgumentSimpleFilter('UDPHeader.source_port==78')
    def check(self, res):
        return self.assertFalse(res)

class TestARPhw_addr(_FilterDefaultTest, unittest.TestCase):
    with open('test_packets/arp_packet', 'rb') as f:
        raw_data = f.read()
    pack_filter = OneArgumentSimpleFilter('ARPHeader.hw_addr_sender==b4:86:55:8c:fa:76')
    all_lvl_pack = pp.parse_raw_packet(raw_data, 'Ethernet')
    one_lvl_pack = all_lvl_pack.data
    

    