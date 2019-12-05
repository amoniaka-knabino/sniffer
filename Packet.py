class Packet:
    def __init__(self, eth_h, net_pr, net_h, trans_pr, trans_h, data):
        self.ethernet_header = eth_h
        self.network_protocol = net_pr
        self.network_header = net_h
        self.transport_protocol = trans_pr
        self.transport_header = trans_h
        self.data = data

    def __str__(self):
        s = str(self.ethernet_header) + '\n'
        if self.network_header is not None:
            s += str(self.network_header) + '\n'
        if self.transport_header is not None:
            s += str(self.transport_header) + '\n'

        return s + '\n\n' + str(self.data)
