#!/usr/bin/env python3

import socket
import sys
from PacketParser import parse_raw_packet
from PcapMaker import PcapMaker
from ArgParser import get_parsed_args
import pack_filter


class Sniffer:
    def __init__(self, interface):
        self.packet_size = 65565
        self.sock = self.create_sock(interface)

    def create_sock(self, interface):
        try:
            sock = socket.socket(socket.AF_PACKET,
                                 socket.SOCK_RAW, socket.ntohs(0x0003))
            try:
                if interface != '':
                    sock.bind((interface, 0))
            except OSError:
                raise OSError("no such device :(")
            return sock
        except PermissionError:
            raise PermissionError('try sudo :)')

    def recieve_pack(self):
        raw_packet = self.sock.recvfrom(self.packet_size)[0]
        packet = parse_raw_packet(raw_packet, "Ethernet")
        return packet

    def recieve_raw(self):
        return self.sock.recvfrom(self.packet_size)[0]

def smart_pack_recieve(sniffer, pack_filter=None):
    if pack_filter is None:
        return sniffer.recieve_pack()
    else:
        while(True):
            pack = sniffer.recieve_pack()
            if pack_filter.filter_all_levels(pack):
                return pack

def write_pcap_mode_without_filtration(sniffer, filename):
    pcap_maker = PcapMaker(filename=filename)
    while True:
        pack = sniffer.recieve_raw()
        pcap_maker.write_packet(pack)

def sniff(args, pack_filter=None):
    sniffer = Sniffer(args.interface)
    if args.console_mode:
        console_print_mode(sniffer, pack_filter)
    else:
        filename = args.filename
        write_pcap_mode_without_filtration(sniffer, filename)

def main():
    args = get_parsed_args()
    filt = None
    if len(args.filter_exr):
        filt = pack_filter.OneArgumentSimpleFilter(args.filter_exr)
    if args.show_filter_list:
        pack_filter.show_help()
    elif args.debug:
        sniff(args, filt)
    else:
        try:
            sniff(args, filt)
        except Exception as e:
            print(f"{e}", file=sys.stderr)
        except KeyboardInterrupt:
            print("Keyboard Interrupt", file=sys.stderr)


def console_print_mode(sniffer, pack_filter):
    while True:
        packet = smart_pack_recieve(sniffer, pack_filter)
        print(str(packet) + '\n\n')


def write_pcap_mode(sniffer):
    pcap_maker = PcapMaker()
    while True:
        packet = sniffer.recieve_pack()
        pcap_maker.write_packet(packet)


if __name__ == "__main__":
    main()
