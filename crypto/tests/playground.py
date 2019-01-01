import sys
import array
import math
import datetime
import time
import struct
from crypto.crypto_tools import Crypto_Kit
from crypto.mt19937 import MT19937
from Crypto.Cipher import AES
from random import randint

cry = Crypto_Kit()
key = cry.generate_random_bytes(randint(5, 20))
original_message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
hash = cry.sha1(key + original_message)

registers = [int(r, 16) for r in list(cry.chunked(8, hash))]


def get_padding(message):
    padding = b''
    og_bit_length = len(message) * 8
    message += bytes([128])
    padding += bytes([128])
    while len(message) % 64 != 56:
        message += bytes([0])
        padding += bytes([0])
    message += struct.pack(">Q", og_bit_length)
    padding += struct.pack(">Q", og_bit_length)
    return padding


for i in range(21):
    padding = get_padding(b'a' * i + original_message)
    new_message = b"comment2=%20like%20a%20pound%20of%20bacon;admin=true;000"

    hash = cry.sha1(
        new_message, *registers,
        (len(original_message) + len(padding) + len(new_message) + i) * 8)

    if cry.validate_sha1_hash(key, hash,
                              original_message + padding + new_message):
        print("got me")
