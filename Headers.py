class IPHeaders():
    def __init__(self):
        self.version
        self.header_length
        self.type_of_service
        self.total_length
        self.identifier
        self.flags
        self.fragmented_offset
        self.ttl
        self.protocol_type
        self.header_checksum
        self.source_address
        self.destination_address
        self.options
        self.padding

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