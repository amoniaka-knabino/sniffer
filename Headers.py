from helpers import *

class EthernetHeader():
    def __init__(self, dest_mac, source_mac, proto):
        self.destination_MAC_address = MAC_address(dest_mac)
        self.source_MAC_address = MAC_address(source_mac)
        self.etherType = EtherType(proto)
        #self.length

        #self.checksum = checksum

class IPv4Headers():
    def __init__(self, ver, h_len, service_type, total_len, id, flags, fr_offset, ttl, proto_type, h_checksum, source_ip, dest_ip, opt, pad):
        self.version = ver
        self.header_length = h_len
        self.type_of_service = service_type
        self.total_length = total_len
        self.identifier = id
        self.flags = flags
        self.fragmented_offset = fr_offset
        self.ttl = ttl
        self.protocol_type = proto_type
        self.header_checksum = h_checksum
        self.source_address = source_ip
        self.destination_address = dest_ip
        self.options = opt
        self.padding = pad

class TCPHeader():
    def __init__():
        self.source_port
        self.destination_port
        self.sequence_number
        self.acknowledgement_number
        self.offset 
        self.reserved
        self.flags
        self.window
        self.checksum
        self.urgent_pointer
        self.options

class UDPHeader():
    def __init__():
        self.source_port
        self.destination_port
        self.length 
        self.checksum

class ICMPHeader():
    def __init__():
        self.type 
        self.code 
        self.checksum

        
#class NetworkHeaders(PacketHeaders):

#class TransportHeaders(PacketHeaders):

"""
class PacketHeaders():
    def __init__(self, sender, receiver):
        self.source_address = sender
        self.destination_address = receiver
"""