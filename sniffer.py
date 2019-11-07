#!/usr/bin/env python3

import socket, sys, argparse
from PacketParser import PacketParser

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
    while True:
        pack = sniffer._recieve_raw()
        #h, d = sniffer.parser.parse_Ethernet(pack)
        #print(h.destination_MAC_address.string(), h.source_MAC_address.string(),  h.etherType.string)
        sniffer.parser.parse(pack)
        
def main():
    parser = argparse.ArgumentParser(description="sniff your traffic <3")
    args = parser.parse_args()

    console_print_mode()

def console_print_mode():
    sniffer = Sniffer()
    while True:
        packet = sniffer.recieve_pack()
        print(packet.string_repr() + '\n\n\n')
    


if __name__ == "__main__":
    main()
    