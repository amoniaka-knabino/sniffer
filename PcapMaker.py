class PcapMaker():
    def __init__(self, filename='', options={}):
        self.filename = self.choose_filename(filename)
        self.file = self.create_pcap()

    def create_pcap(self):
        try:
            return open(self.filename, 'wb+')
        except:
            pass
    
    def choose_filename(self, filename):
        return filename
    
    def write_packet(self, packet):
        pass