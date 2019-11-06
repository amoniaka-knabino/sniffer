class Packet():
    def __init__(self, eth_h, net_pr, net_h, trans_pr, trans_h, data):
        self.ethernet_headers = eth_h
        self.network_protocol = net_pr
        self.network_headers = net_h
        self.transport_protocol = trans_pr
        self.transport_headers = trans_h
        self.data = data
