from Packet import Packet
from Headers import Header

class OneArgumentSimpleFilter:
    def __init__(self, expr):
        h, self.value = expr.split('==')
        self.classname, self.fieldname = h.split('.')
    
    def filter_one_level(self, pack):
        '''
        we use str(getattr(..)) because we suppose that user will write values in str format by default
        '''
        if type(pack.header).__name__ == self.classname:
            if str(getattr(pack.header, self.fieldname)) == self.value:
                return True
        else:
            return False
    
    def filter_all_levels(self, full_pack):
        current_pack = full_pack
        while(True):
            res = self.filter_one_level(current_pack)
            if res:
                return True
            elif type(current_pack.data) is Packet:
                current_pack = current_pack.data 
            else:
                return False

def show_help():
    print(("To filter you should write: {classname}.{fieldname}=={value}\n"
            "Here is list of filters. Format: {classname} : [{fieldname}, ..]\n\n")
            + show_filter_list())

def show_filter_list():
    ans = ''
    for h in all_subclasses(Header):
        if not len(h.FIELDS):
            continue
        attrs = [x[1] for x in h.FIELDS]
        ans+=(f"{h.__name__} : {attrs}\n\n")
    return ans

def all_subclasses(cls):
    return set(cls.__subclasses__()).union(
        [s for c in cls.__subclasses__() for s in all_subclasses(c)])



class StringFilter():
    def __init__(self, network_protocol=None, transport_protocol=None,
                ip=None, port=None):
        self.ip = ip
        self.port = port
        self.network_protocol = self.set_network_filter(network_protocol)
        self.transport_protocol = self.set_trasport_filter(transport_protocol)
    
    def set_network_filter(self, nw_proto_str):
        if nw_proto_str is None and self.ip is None:
            return None
        a = nw_proto_str.upper()
        if a == "ARP":
            return "ARP"
        if a == "IP" or a == "IPV4" or self.ip is not None:
            return "IPv4"

    def set_trasport_filter(self, proto_str):
        if proto_str is None:
            return None
        return proto_str.upper()
    
    def check_packet(self, packet):
        if self.network_protocol is not None:
            if not (str( packet.ethernet_header.ether_type) == self.network_protocol ):
                return False
        if self.ip is not None:
            
            if not (str(packet.network_header.source_address) == self.ip
                    or str(packet.network_header.destination_address) == self.ip):
                    return False
