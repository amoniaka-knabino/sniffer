#!/usr/bin/env python3

import socket, sys, argparse
from PacketParser import PacketParser
from PcapMaker import PcapMaker

class Sniffer():
    def __init__(self):
        self.packet_size = 65565
        self.sock = self.create_sock()
        self.parser = PacketParser()

    def create_sock(self):
        try:
            s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
            return s
        except PermissionError:
            print('try sudo :)')
            sys.exit()
    
    def recieve_pack(self):
        raw_packet = self.sock.recvfrom(self.packet_size)[0]
        packet = self.parser.parse(raw_packet)
        return packet
    
    def _recieve_raw(self):
        return self.sock.recvfrom(self.packet_size)[0]

def debug():
    sniffer = Sniffer()
    pcap_maker = PcapMaker()
    for i in range(1000):
        pack = sniffer._recieve_raw()
        pcap_maker.write_packet(pack)
        
def main():
    parser = argparse.ArgumentParser(description="sniff your traffic <3")
    args = parser.parse_args()

    #debug()
    console_print_mode()


def console_print_mode():
    sniffer = Sniffer()
    while True:
        packet = sniffer.recieve_pack()
        print(packet.string_repr() + '\n\n\n')


def write_pcap_mode():
    sniffer = Sniffer()
    pcap_maker = PcapMaker()
    while True:
        packet = sniffer.recieve_pack()
        pcap_maker.write_packet(packet)


if __name__ == "__main__":
    debug()
    