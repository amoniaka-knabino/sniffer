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

pack_filter.py - filter for parsed packets (now is only 1 arg simple filter)


# Usage

./sniffer.py --help

./sniffer.py - sniff traffic and write it to tempfile

./sniffer.py -d - run sniffer in debug mode (when you get exception, you'll see stack trace)

./sniffer.py -c - console writing mode

./sniffer.py -i eth0 - sniff traffic from eth0 interface

./sniffer.py -f my.pcap - sniff traffic and write it to "my.pcap"

./sniffer.py -c --filter EthernetHeader.ether_type==ARP - sniff and print only ARP packs

./sniffer.py -l - look details about filtering


# Details of realization

Sniffer based on raw sockets.

Now is simple filtration supported (ONLY IN CONSOLE MODE). See details: ./sniffer.py -l
