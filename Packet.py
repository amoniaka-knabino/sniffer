class Packet():
    def __init__(self, eth_h, net_pr, net_h, trans_pr, trans_h, data):
        self.ethernet_header = eth_h
        self.network_protocol = net_pr
        self.network_header = net_h
        self.transport_protocol = trans_pr
        self.transport_header = trans_h
        self.data = data
    
    def string_repr(self):
        s = self.ethernet_header.string_repr() + '\n'
        if self.network_header is not None:
            s += self.network_header.string_repr() + '\n'
        if self.transport_header is not None:
            s += self.transport_header.string_repr() + '\n'

        return s +'\n\n' + str(self.data)

