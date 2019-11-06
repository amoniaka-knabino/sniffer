from Headers import *

class Packet():
    def __init__(self):
        self.network_protocol
        self.network_headers
        self.transport_protocol
        self.transport_headers
        self.data

class EthernetPacket():
    def __init__(self, raw_data):
        self.