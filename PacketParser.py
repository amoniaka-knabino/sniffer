import Packet

class PackerParser():
    def __init__(self):
        pass

    def parse(self, raw_data):
        packet = Packet.Packet()
        return EthernetHeader, packet
    
    def parse_Ethernet(self, raw_data):
        return headers, data
    
    def parse_ip(self, raw_data):
        pass

    def parse_tcp(self, raw_data):
        pass

    def parse_udp(self, raw_data):
        pass

    def parse_icmp(self, raw_data):
        pass
    
    
