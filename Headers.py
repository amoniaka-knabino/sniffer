#import helpers as h

from helpers import *

class Header:
    # format of FIELDS item: [print_name, var_name, type]
    # format of args = [item_value, item_value ...]

    # eval(f"{self.FIELDS[i][2]}({args[i]})")
    FIELDS=[]
    def __init__(self, *args):
        for i in range(len(self.FIELDS)):
            setattr(self, self.FIELDS[i][1],
                    list(map(self.FIELDS[i][2], [args[i]]))[0])

    def __str__(self):
        args_dict = {}
        for i in self.FIELDS:
            value = getattr(self, i[1])
            args_dict[i[0]] = value
        return ', '.join([f'{k} : {v}' for (k,v) in args_dict.items()])


class NetworkHeader(Header):
    def get_parent_header_type(self):
        return EthernetHeader


class TransportHeader(Header):
    def get_parent_header_type(self):
        return NetworkHeader


class EthernetHeader(Header):
    FIELDS  = [["Destination MAC", "destination_MAC_address", MAC_address],
                ["Source MAC", "source_MAC_address", MAC_address],
                ["EtherType", "ether_type", EtherType]]


class IPv4Header(NetworkHeader):
    def __init__(self, ver, h_len, service_type,
                 total_len, pack_id, flags, fr_offset, ttl,
                 proto_type, h_checksum, source_ip, dest_ip, opt_pad):
        self.version = int(ver)
        self.header_length = int(h_len)
        self.type_of_service = service_type
        self.total_length = int(total_len)
        self.identifier = pack_id
        self.flags = FragmentationFlag(flags)
        self.fragmented_offset = int(fr_offset)
        self.ttl = int(ttl)
        self.protocol_type = TransportProtocol(bytes([proto_type]))
        self.header_checksum = int(h_checksum)
        self.source_address = IPv4Address(source_ip)
        self.destination_address = IPv4Address(dest_ip)
        self.options_with_pad = opt_pad

    def __str__(self):  
        args = [self.version, self.header_length,
                self.type_of_service, self.total_length,
                self.identifier, str(self.flags),
                self.fragmented_offset, self.ttl,
                str(self.protocol_type), self.header_checksum,
                str(self.source_address),
                str(self.destination_address), self.options_with_pad]

        str_template = """IP ver = {}, header length = {}, TOS = {},
total length = {}, id = {} , flags = {} , fragmented offset = {},
TTL = {}, protocol = {} , checksum = {}
source = {} , destination = {}"""

        return str_template.format(*args)


class ARPHeader(NetworkHeader):
    def __init__(self, hw_type_bytes, proto_type_bytes, hw_addr_byte_len,
                 proto_addr_byte_len, operation_code, hw_addr_sender,
                 proto_addr_sender, hw_addr_target, proto_addr_target):
        self.hardware_type = HardwareType(hw_type_bytes)
        self.protocol_type = self._set_proto_type(proto_type_bytes)
        self.hw_addr_byte_len = hw_addr_byte_len
        self.proto_addr_byte_len = proto_addr_byte_len
        self.operation_code = operation_code
        self.hw_addr_sender = self._set_hw_addr(hw_addr_sender)
        self.proto_addr_sender = self._set_proto_addr(proto_addr_sender)
        self.hw_addr_target = self._set_hw_addr(hw_addr_target)
        self.proto_addr_target = self._set_proto_addr(proto_addr_target)

    def _set_proto_type(self, proto_type_bytes):
        if str(self.hardware_type) == "Ethernet":
            return EtherType(proto_type_bytes)
        else:
            return ByteIntStrData(proto_type_bytes)

    def _set_hw_addr(self, addr_bytes):
        if str(self.hardware_type) == "Ethernet":
            return MAC_address(addr_bytes)
        else:
            return addr_bytes

    def _set_proto_addr(self, proto_addr_bytes):
        if str(self.protocol_type) == "IPv4":
            return IPv4Address(proto_addr_bytes)
        else:
            return proto_addr_bytes


class ICMPHeader(TransportHeader):
    """
    https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    """

    def __init__(self, type_byte, code_byte, checksum_int):
        self.type = ICMPType(bytes([type_byte]))
        self.code = bytes([code_byte])
        self.checksum = int(checksum_int)


class TCPHeader(TransportHeader):
    def __init__(self, source_port, destination_port, sequence_number,
                 acknowledgement_number, offset, flags,
                 window, checksum, urgent_pointer, options):
        self.source_port = unpack("!H", source_port)[0]
        self.destination_port = unpack("!H", destination_port)[0]
        self.sequence_number = sequence_number
        self.acknowledgement_number = acknowledgement_number
        self.offset = offset

        self.flags = flags
        self.window = window
        self.checksum = checksum
        self.urgent_pointer = urgent_pointer
        self.options = options


class UDPHeader(TransportHeader):
    def __init__(self, source_port, destination_port, length, checksum):
        self.source_port = unpack("!H", source_port)[0]
        self.destination_port = unpack("!H", destination_port)[0]
        self.length = unpack("!H", length)[0]
        self.checksum = checksum
