from hexdump import hexdump
import sys
import io
from contextlib import redirect_stdout


class Packet:
    def __init__(self, header, data):
        self.header = header
        self.data = data

    def __str__(self):
        if self.header is None:

            return get_hex_dump(self.data)
        else:
            if isinstance(self.data, Packet):
                return (f"{self.header}\n\n"
                        f"{self.data}")
            else:
                return get_hex_dump(self.data)


def get_hex_dump(data):
    with io.StringIO() as buf, redirect_stdout(buf):
        hexdump(data)
        output = buf.getvalue()
    return output
