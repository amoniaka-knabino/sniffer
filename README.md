# Sniffer

Program for interception and logging network traffic.
You need to run this program with super-user rights. (as usual sniffer)


# Requieremnts

python>=3.7

# Files

ArgParser.py - module for arguments parsing
Headers.py - network, transport headers classes 
helpers.py - helping modules
Packet.py - Captured Packets
PcapMaker.py - pcap file writer 
sniffer.py - start point of the program

# Usage

./sniffer.py --help
./sniffer.py - sniff traffic and write it to "temp.pcap"
./sniffer.py -c - console writing mode (debug)
./sniffer.py -f my.pcap - sniff traffic and write it to "my.pcap"

# Details of realization

Sniffer based on raw sockets.