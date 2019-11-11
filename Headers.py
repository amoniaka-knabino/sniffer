from helpers import *


class Header():
    def __str__(self):
        d = self.__dict__
        return ', '.join([str(k) + ' : ' + str(d[k]) for k in d])

    def string_repr(self):
        d = self.__dict__
        return ', '.join([str(k) + ' : ' + str(d[k]) for k in d])


class EthernetHeader(Header):
    def __init__(self, dest_mac, source_mac, proto):
        self.destination_MAC_address = MAC_address(dest_mac)
        self.source_MAC_address = MAC_address(source_mac)
        self.etherType = EtherType(proto)
        # self.length
        #self.checksum = checksum

    def string_repr(self):
        args = [self.source_MAC_address.to_string(
        ), self.destination_MAC_address.to_string(), self.etherType.string]

        str_template = "Source MAC = {} , Destination MAC = {} , EtherType = {}"

        return str_template.format(*args)


class IPv4Header(Header):
    def __init__(self, ver, h_len, service_type, total_len, pack_id, flags, fr_offset, ttl, proto_type, h_checksum, source_ip, dest_ip, opt_pad):
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

    def string_repr(self):
        args = [self.version, self.header_length, self.type_of_service, self.total_length,
                self.identifier, self.flags.to_string(
                ), self.fragmented_offset, self.ttl, self.protocol_type.to_string(), self.header_checksum,
                self.source_address.to_string(), self.destination_address.string, self.options_with_pad]

        str_template = """IP ver = {} , header length = {} , TOS = {} , total length = {}
id = {} , flags = {} , fragmented offset = {},
TTL = {}, protocol = {} , checksum = {}
source = {} , destination = {}"""

        return str_template.format(*args)


class ICMPHeader(Header):
    """
    https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    """
    def __init__(self, type_byte, code_byte, checksum_int):
        self.type = ICMPType(bytes([type_byte]))
        self.code = bytes([code_byte])
        self.checksum = int(checksum_int)


class ARPHeader(Header):
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


class DHCPHeader(Header):
    """
    https://zametkinapolyah.ru/kompyuternye-seti/9-3-struktura-format-i-naznachenie-dhcp-paketov-soobshhenij-dhcpdiscover-dhcpoffer-dhcprequest-i-dhcpack.html#932__DHCP
    """
    def __init__(self, op_code, hw_type, hw_len,
                hops, transaction_id, secs_elapsed, flags,
                clentIP, yourIP, serverIP, gatewayIP,
                client_hw_address, server_host_name, boot_file,
                opts):
        self.op_code = op_code
        self.hw_type = hw_type
        self.hw_len = int(hw_len)
        self.hops = hops
        self.transaction_id = transaction_id
        self.secs_elapsed = secs_elapsed
        self.flags = flags
        self.clientIP = IPv4Address(clentIP)
        self.yourIP = IPv4Address(yourIP)
        self.serverIP = IPv4Address(serverIP)
        self.gatewayIP = IPv4Address(gatewayIP)
        self.client_hw_address = client_hw_address
        self.server_host_name = server_host_name
        self.boot_file = boot_file
        self.opts = opts



class TCPHeader(Header):
    def __init__(self, source_port, destination_port, sequence_number,
                acknowledgement_number, offset, flags,
                window, checksum, urgent_pointer, options):
        self.source_port = unpack("!H", source_port)[0]
        self.destination_port = unpack("!H",destination_port)[0]
        self.sequence_number = sequence_number
        self.acknowledgement_number = acknowledgement_number
        self.offset = offset
        #self.reserved = reversed
        self.flags = flags
        self.window = window
        self.checksum = checksum
        self.urgent_pointer = urgent_pointer
        self.options = options


class UDPHeader(Header):
    def __init__(self, source_port, destination_port, length, checksum):
        self.source_port = unpack("!H", source_port)[0]
        self.destination_port = unpack("!H",destination_port)[0]
        self.length = unpack("!H", length)[0]
        self.checksum = checksum


# class NetworkHeaders(PacketHeaders):

# class TransportHeaders(PacketHeaders):


