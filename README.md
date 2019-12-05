# Sniffer

Program for interception and logging network traffic.
You need to run this program with super-user rights. (as usual sniffer)


# Requieremnts

python>=3.7.4

# Files

tests/ - tests
tests_packets/ - raw packets captured with other sniffer, used for testing
ArgParser.py - module for console arguments parsing
Headers.py - headers classes 
helpers.py - small helping classes and functions
Packet.py - parsed captured Packets class
PcapMaker.py - pcap file writer 
PacketParser.py - parse raw sockets to Packet class
sniffer.py - start point of the program

# Usage

./sniffer.py --help
./sniffer.py - sniff traffic and write it to "temp.pcap"
./sniffer.py -c - console writing mode (debug)
./sniffer.py -f my.pcap - sniff traffic and write it to "my.pcap"

# Details of realization

Sniffer based on raw sockets.