from helpers import *

class EthernetHeader():
    def __init__(self, dest_mac, source_mac, proto):
        self.destination_MAC_address = MAC_address(dest_mac)
        self.source_MAC_address = MAC_address(source_mac)
        self.etherType = EtherType(proto)
        #self.length

        #self.checksum = checksum
    
    def string_repr(self):
        args = [self.source_MAC_address.to_string(), self.destination_MAC_address.to_string(), self.etherType.string]

        str_template = "Source MAC = {} , Destination MAC = {} , EtherType = {}"

        return str_template.format(*args)

class IPv4Header():
    def __init__(self, ver, h_len, service_type, total_len, pack_id, flags, fr_offset, ttl, proto_type, h_checksum, source_ip, dest_ip, opt_pad):
        self.version = int(ver)
        self.header_length = int(h_len)
        self.type_of_service = service_type
        self.total_length = int(total_len)
        self.identifier = pack_id
        self.flags = FragmentationFlag(flags)
        self.fragmented_offset = int(fr_offset)
        self.ttl = int(ttl)
        self.protocol_type = TransportProtocol(proto_type)
        self.header_checksum = int(h_checksum)
        self.source_address = IPAddress(source_ip)
        self.destination_address = IPAddress(dest_ip)
        self.options_with_pad = opt_pad
    
    def string_repr(self):
        args = [self.version, self.header_length, self.type_of_service, self.total_length,
        self.identifier, self.flags.to_string(), self.fragmented_offset, self.ttl, self.protocol_type.to_string(), self.header_checksum,
        self.source_address.to_string(), self.destination_address.string, self.options_with_pad]

        str_template = """IP ver = {} , header length = {} , TOS = {} , total length = {}
id = {} , flags = {} , fragmented offset = {},
TTL = {}, protocol = {} , checksum = {}
source = {} , destination = {}"""

        return str_template.format(*args)

class ICMPHeader():
    def __init__(self):
        
        self.type 
        self.code 
        self.checksum

class ARPHeader():
    def __init__(self):
        pass

class DHCPHeader():
    def __init__(self):
        pass


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

        
#class NetworkHeaders(PacketHeaders):

#class TransportHeaders(PacketHeaders):

"""
class PacketHeaders():
    def __init__(self, sender, receiver):
        self.source_address = sender
        self.destination_address = receiver
"""