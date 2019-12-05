#!/usr/bin/env python3

import socket
import sys
from PacketParser import parse_all_packet
from PcapMaker import PcapMaker
from ArgParser import get_parsed_args


class Sniffer:
    def __init__(self):
        self.packet_size = 65565
        self.sock = self.create_sock()

    def create_sock(self):
        try:
            sock = socket.socket(socket.AF_PACKET,
                              socket.SOCK_RAW, socket.ntohs(0x0003))
            return sock
        except PermissionError:
            print('try sudo :)', file=sys.stderr)
            sys.exit(1)

    def recieve_pack(self):
        raw_packet = self.sock.recvfrom(self.packet_size)[0]
        packet = parse_all_packet(raw_packet)
        return packet

    def recieve_raw(self):
        return self.sock.recvfrom(self.packet_size)[0]


def write_pcap_mode_without_filtration(filename):
    sniffer = Sniffer()
    pcap_maker = PcapMaker(filename=filename)
    while True:
        pack = sniffer.recieve_raw()
        pcap_maker.write_packet(pack)


def main():
    args = get_parsed_args()
    if args.console_mode:
        console_print_mode()
    else:
        filename = args.filename or 'temp.pcap'
        write_pcap_mode_without_filtration(filename)


def console_print_mode():
    sniffer = Sniffer()
    while True:
        packet = sniffer.recieve_pack()
        print(str(packet)+ '\n\n\n')


def write_pcap_mode():
    sniffer = Sniffer()
    pcap_maker = PcapMaker()
    while True:
        packet = sniffer.recieve_pack()
        pcap_maker.write_packet(packet)


if __name__ == "__main__":
    main()
