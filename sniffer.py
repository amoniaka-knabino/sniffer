import socket, sys

packet_size = 65565

def create_sock():
    try:
        s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        return s
    except PermissionError:
        print('You should run sniffer with sudo')
        sys.exit()


def main():
    sock = create_sock()
    while True:
        packet = sock.recvfrom(packet_size)
        packet = packet[0]

if __name__ == "__main__":
    main()