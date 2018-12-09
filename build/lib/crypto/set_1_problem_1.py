class Set1Problem1():
    def decode(self, hex):
        return hex.decode("hex").encode("base64")
