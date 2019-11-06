import socket
from struct import unpack

class MAC_address():
    def __init__(self, mac_bytes):
        self.bytes = mac_bytes
    
    def string(self):
        a = self.bytes
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0] , a[1] , a[2], a[3], a[4] , a[5])
        return b

class EtherType():
    #доработать
    int_to_name = { 8 : "IPv4"}

    def _extract_int(self, type_bytes):
        # мб стоит проверять byte-order
        return unpack('H' , type_bytes)[0]

    def __init__(self, type_bytes):
        self.bytes = type_bytes
        self.int = self._extract_int(type_bytes)
        try:
            self.string = self.int_to_name[self.int]
        except KeyError:
            self.string = "unknown"


