class Packet:
    def __init__(self, header, data):
        self.header = header
        self.data = data

    def __str__(self):
        return (
                f"{self.header}\n"
                f"{self.data}\n")
