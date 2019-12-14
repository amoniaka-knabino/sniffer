from Packet import Packet
from Headers import Header


class OneArgumentSimpleFilter:
    def __init__(self, expr):
        h, self.value = expr.split('==')
        self.classname, self.fieldname = h.split('.')

    def filter_one_level(self, pack):
        '''
        we use str(getattr(..)) because we suppose that
        user will write values in str format by default
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
    fl = show_filter_list()
    start = ("To filter you should write: "
             "{classname}.{fieldname}=={value}\n"
             "Here is list of filters. "
             "Format: {classname} : [{fieldname}, ..]\n\n")
    return start + fl


def show_filter_list():
    ans = ''
    for h in all_subclasses(Header):
        if not len(h.FIELDS):
            continue
        attrs = [x[1] for x in h.FIELDS]
        ans += (f"{h.__name__} : {attrs}\n\n")
    return ans


def all_subclasses(cls):
    return set(cls.__subclasses__()).union(
        [s for c in cls.__subclasses__() for s in all_subclasses(c)])
