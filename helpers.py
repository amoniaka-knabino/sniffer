import socket
from struct import unpack


class ByteIntStrData():
    """
    Neccessary: byteorder in _extract_int == byteorder in keys in int_to_name
    """

    def __init__(self, type_bytes):
        self.bytes = type_bytes
        self.int = self._extract_int(type_bytes)
        self.string = self._convert_int_to_name()

    def _extract_int(self, type_bytes):
        return int.from_bytes(type_bytes, byteorder='little')

    def to_string(self):
        return self.string

    def __str__(self):
        return self.string

    def _convert_int_to_name(self):
        try:
            return self._get_int_to_name_dic()[self.int]
        except KeyError:
            return "unknown"

    def _get_int_to_name_dic(self):
        return {}


class HardwareType(ByteIntStrData):
    def _get_int_to_name_dic(self):
        return {0x0100: "Ethernet"}


class EtherType(ByteIntStrData):
    def _get_int_to_name_dic(self):
        int_to_name = {8: "IPv4", 0x0608: "ARP", 0xDD86: "IPv6",
                       0x4788: "MPLS unicast", 0x4888: "MPLS multicast", 0x8E88: "EAPoL"}
        return int_to_name


class TransportProtocol(ByteIntStrData):
    def _get_int_to_name_dic(self):
        int_to_name = {17: "UDP", 6: "TCP", 1: "ICMP", 88: "IGPR", 89: "OSPF"}
        return int_to_name


class IPv4Address():
    def __init__(self, adr_bytes):
        self.bytes = adr_bytes
        self.string = socket.inet_ntoa(adr_bytes)

    def to_string(self):
        return self.string

    def __str__(self):
        return self.string


class MAC_address():
    def __init__(self, mac_bytes):
        self.bytes = mac_bytes
        self.string = self.to_string()

    def to_string(self):
        a = self.bytes
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            a[0], a[1], a[2], a[3], a[4], a[5])
        return b

    def __str__(self):
        a = self.bytes
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            a[0], a[1], a[2], a[3], a[4], a[5])
        return b


class FragmentationFlag():
    int_to_name = {2: "Don't fragment  ",
                   1: "More fragments", 3: "Fragmentation is prohibited"}

    def __init__(self, flag_int):
        self.int = flag_int
        self.bin = bin(flag_int)[2:]
        try:
            self.string = self.int_to_name[self.int]
        except KeyError:
            self.string = "unknown " + str(self.int)

    def to_string(self):
        return self.string

    def __str__(self):
        return self.string


class ARPOpCode(ByteIntStrData):
    def _get_int_to_name_dic(self):
        """
        http://www.networksorcery.com/enp/protocol/arp.htm#Opcode
        """
        return {0: "reserved", 1: "request", 2: "reply",
                3: "request reverse", 4: "reply reverse",
                5: "DRARP request", 6: "DRARP peply", 7: "DRARP Error",
                8: "InARP Request", 9: "InARP Reply", 10: "ARP NAK"}


class ICMPType(ByteIntStrData):
    def _get_int_to_name_dic(self):
        """
        http://www.rhyshaden.com/icmp.htm
        """
        return {0: "Echo Reply", 3: "Destination Unreachable",
                4: "Source Queench", 5:"Redirect", 8: "Echo Request",
                11: "Time Exceeded", 12:"Parameter Problem",
                13: "Timestamp request", 14:"Timestamp Reply",
                17:"Address mask request", 18: "Address mask response"}

