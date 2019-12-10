class Packet:
    def __init__(self, header, data):
        self.header = header
        self.data = data

    def __str__(self):
        if self.header is None:
            return str(self.data)
        return (
            f"{self.header}\n"
            f"{self.data}\n")
