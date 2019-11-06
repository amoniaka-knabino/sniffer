import socket, sys
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


def main():
    sniffer = Sniffer()
    while True:
        pack = sniffer._recieve_raw()
        h, d = sniffer.parser.parse_Ethernet(pack)
        print(h.source_MAC_address.string(), h.destination_MAC_address.string(), h.protocol.string)
        

if __name__ == "__main__":
    main()