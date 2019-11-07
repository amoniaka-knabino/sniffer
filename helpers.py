import socket
from struct import unpack

class MAC_address():
    def __init__(self, mac_bytes):
        self.bytes = mac_bytes
        self.string = self.to_string()
    
    def to_string(self):
        a = self.bytes
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0] , a[1] , a[2], a[3], a[4] , a[5])
        return b

class EtherType():
    int_to_name = { 8 : "IPv4" , 0x0608 : "ARP", 0xDD86 : "IPv6",
    0x4788 : "MPLS unicast", 0x4888 : "MPLS multicast", 0x8E88 : "EAPoL" }

    def _extract_int(self, type_bytes):
        # мб стоит проверять byte-order
        return unpack('H' , type_bytes)[0]
    
    def to_string(self):
        return self.string

    def __init__(self, type_bytes):
        self.bytes = type_bytes
        self.int = self._extract_int(type_bytes)
        try:
            self.string = self.int_to_name[self.int]
        except KeyError:
            self.string = "unknown"

class TransportProtocol():
    int_to_name = { 17 : "UDP", 6 : "TCP", 1 : "ICMP", 88 : "IGPR", 89 : "OSPF"}

    def __init__(self, type_int):
        self.bytes = bytes([type_int])
        self.int = type_int
        try:
            self.string = self.int_to_name[self.int]
        except KeyError:
            self.string = "unknown"
    
    def to_string(self):
        return self.string

class IPAddress():
    def __init__(self, adr_bytes):
        self.bytes = adr_bytes
        self.string = socket.inet_ntoa(adr_bytes)
    
    def to_string(self):
        return self.string

class FragmentationFlag():
    int_to_name = {2 : "Don't fragment  ", 1: "More fragments", 3: "Fragmentation is prohibited"}
    def __init__(self, flag_int):
        self.int = flag_int
        self.bin = bin(flag_int)[2:]
        self.string = self.int_to_name[flag_int]
    
    def to_string(self):
        return self.string

