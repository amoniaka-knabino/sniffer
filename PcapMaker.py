from struct import pack
from time import time
import random
import string
from os.path import exists, basename, splitext

class PcapMaker:
    """
    http://www.kroosec.com/2012/10/a-look-at-pcap-file-format.html
    https://wiki.wireshark.org/Development/LibpcapFileFormat
    """

    def __init__(self, filename='', options={}, timezone=5):
        self.filename = self.choose_filename(filename)
        self.file = self.create_pcap_file()
        self.thiszone = 5*3600
        self.snaplen = 65535

        self.initialize_pcap_file()

    def create_pcap_file(self):
        return open(self.filename, 'wb+')
    
    def create_pcap_tempfile(self):
        pass

    def initialize_pcap_file(self):
        self.write_global_header()

    def write_global_header(self):
        magic_number = bytes.fromhex("d4c3b2a1")
        major_ver = pack("H", 2)
        minor_ver = pack("H", 4)
        thiszone = pack("i", self.thiszone)
        sigfigs = b"\x00"*4
        snaplen = pack("i", self.snaplen)
        network = pack("i", 1)

        data_to_write = [magic_number, major_ver,
                         minor_ver, thiszone, sigfigs, snaplen, network]

        for x in data_to_write:
            self.file.write(x)

    def choose_filename(self, filename):
        while True:
            if exists(filename):
                base = splitext(basename(filename))
                print(base)
                new_filename = ''
                for i in range(len(base)-1):
                    new_filename += base[i]
                new_filename += f"_{gen_rand_str()}{base[-1]}"
                filename = new_filename
            else:
                print(filename)
                return filename
        

    def write_packet(self, raw_packet):
        self.write_packet_header(raw_packet)
        self.file.write(raw_packet)

    def write_packet_header(self, packet):
        ts_sec = pack("i", int(time()))
        # how many microsec was taken to capture the packet
        ts_usec = pack("i", 0)
        incl_len = pack("i", len(packet) % self.snaplen)
        orig_len = pack("i", len(packet))

        data_to_write = [ts_sec, ts_usec, incl_len, orig_len]

        for x in data_to_write:
            self.file.write(x)

def gen_rand_str(str_len=5):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(str_len))