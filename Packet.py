class Packet():
    def __init__(self, eth_h, net_pr, net_h, trans_pr, trans_h, data):
        self.ethernet_header = eth_h
        self.network_protocol = net_pr
        self.network_header = net_h
        self.transport_protocol = trans_pr
        self.transport_header = trans_h
        self.data = data
    
    def string_repr(self):
        return self.ethernet_header.string_repr() + '\n' + self.network_header.string_repr() + '\n\n' + str(self.data)
