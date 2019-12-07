#import helpers as h

import helpers as h
from struct import unpack

for_post_initialization = lambda x : x

class Header:
    """
    format of FIELDS item: [print_name, var_name, func for map]
    format of args = [item_value, item_value ...]
    """
    # eval(f"{self.FIELDS[i][2]}({args[i]})")
    FIELDS = []

    def __init__(self, *args):
        for i in range(len(self.FIELDS)):
            setattr(self, self.FIELDS[i][1],
                    list(map(self.FIELDS[i][2], [args[i]]))[0])
        self.post_init()

    def __str__(self):
        args_dict = {}
        for i in self.FIELDS:
            value = getattr(self, i[1])
            args_dict[i[0]] = value
        return ',  '.join([f'{k} : {v}' for (k, v) in args_dict.items()])
    
    def post_init(self):
        pass


class NetworkHeader(Header):
    def get_parent_header_type(self):
        return EthernetHeader


class TransportHeader(Header):
    def get_parent_header_type(self):
        return NetworkHeader


class EthernetHeader(Header):
    FIELDS = [["Destination MAC", "destination_MAC_address", h.MAC_address],
              ["Source MAC", "source_MAC_address", h.MAC_address],
              ["EtherType", "ether_type", h.EtherType]]


class IPv4Header(NetworkHeader):
    FIELDS = [["Version", "version", int],
              ["Header Length", "header_length", int],
              ["Type of Service", "type_of_service", lambda x: x],
              ["Total Length", "total_length", int],
              ["Identifier", "identifier", lambda x: x],
              ["Flags", "flags", h.FragmentationFlag],
              ["Fragmentation offset", "fragmented_offset", int],
              ["TTL", "ttl", int],
              ["Protocol Type", "protocol_type", lambda x: h.TransportProtocol(bytes([x]))],
              ["Header Checksum", "header_checksum", int],
              ["Source IP", "source_address", h.IPv4Address],
              ["Destination IP", "destination_address", h.IPv4Address],
              ["Options & Padding", "options_with_pad", lambda x: x]
              ]


class ARPHeader(NetworkHeader):
    FIELDS = [
        ["Hardware Type", "hardware_type", h.HardwareType],
        ["Protocol Type", "protocol_type", for_post_initialization],
        ["HW address length", "hw_addr_byte_len", lambda x: x],
        ["Protocol address length", "proto_addr_byte_len", lambda x: x],
        ["Operation Code", "operation_code", lambda x: x],
        ["Hardware Address Sender", "hw_addr_sender", for_post_initialization],
        ["Protocol Address Sender", "proto_addr_sender", for_post_initialization],
        ["Hardware Address Target", "hw_addr_target", for_post_initialization],
        ["Protocol Address Target", "proto_addr_target", for_post_initialization]
        
    ]

    def post_init(self):
        self.protocol_type = self._set_proto_type(self.protocol_type)
        self.hw_addr_sender = self._set_hw_addr(self.hw_addr_sender)
        self.proto_addr_sender = self._set_proto_addr(self.proto_addr_sender)
        self.hw_addr_target = self._set_hw_addr(self.hw_addr_target)
        self.proto_addr_target = self._set_proto_addr(self.proto_addr_target)


    def _set_proto_type(self, proto_type_bytes):
        if str(self.hardware_type) == "Ethernet":
            return h.EtherType(proto_type_bytes)
        else:
            return h.ByteIntStrData(proto_type_bytes)

    def _set_hw_addr(self, addr_bytes):
        if str(self.hardware_type) == "Ethernet":
            return h.MAC_address(addr_bytes)
        else:
            return addr_bytes

    def _set_proto_addr(self, proto_addr_bytes):
        if str(self.protocol_type) == "IPv4":
            return h.IPv4Address(proto_addr_bytes)
        else:
            return proto_addr_bytes


class ICMPHeader(TransportHeader):
    """
    https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    """

    FIELDS = [["Type", "type", h.ICMPType],
            ["Code", "code", lambda x : int.from_bytes(x, "big")],
            ["Checksum", "checksum", lambda x : int.from_bytes(x, "big")]
    ]


class TCPHeader(TransportHeader):
    FIELDS = [["Source Port", "source_port", lambda x : unpack("!H", x)[0]],
                ["Destination Port", 'destination_port', lambda x : unpack("!H", x)[0]],
                ["Sequence number", "sequence_number", lambda x : unpack("!L", x)[0]],
                ["Acknowledgement number", "acknowledgement_number", lambda x : unpack("!L", x)[0]],
                ["Offset", "offset", lambda x: x],
                ["Flags", "flags", lambda x: x],
                ["Window", "window", lambda x: x],
                ["Checksum", 'checksum', lambda x : unpack("!H", x)[0]],
                ["Urgent Pointer", "urgent_pointer", lambda x: x],
                ["Options", "options", lambda x: x]
    ]

class UDPHeader(TransportHeader):
    FIELDS = [["Source Port", "source_port", lambda x : unpack("!H", x)[0]],
                ["Destination Port", 'destination_port', lambda x : unpack("!H", x)[0]],
                ["Length", "length", lambda x : unpack("!H", x)[0]],
                ["Checksum", "checksum", lambda x : x]]

