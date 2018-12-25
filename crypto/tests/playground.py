import sys
import array
import math
from crypto.crypto_tools import Crypto_Kit
from Crypto.Cipher import AES
from random import randint

cryp = Crypto_Kit()
unknown_string = """
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK
"""

unencrypted_string = cryp.decode_base64(unknown_string)

result = []


def get_unknown_bytes():
    global result
    for i in range(100):
        result = cryp.ecb_encryption_oracle_random_prefix(
            b'a' * i, unencrypted_string)
        byte_set = set()
        prefix_bytes = b''
        split_bytes = list(cryp.chunked(16, result))
        for byte in split_bytes:
            if byte in byte_set:
                return i, len(prefix_bytes)
            prefix_bytes += byte
            byte_set.add(byte)


cipher_length = 16
bytes_amount, ignore_bytes = get_unknown_bytes()
bytes_amount -= 16
known_bytes = bytearray(bytes([0] * 15))

chunks = list(cryp.chunked(cipher_length, result[ignore_bytes:]))
decrypted_bytes = b''

for chunk in range(len(chunks)):
    block = chunk * cipher_length

    for i in range(cipher_length):
        dictionary = {}
        offset = cipher_length - 1 - i
        bytes_we_know = bytes(known_bytes[-(cipher_length - 1):])
        for j in range(256):
            guess = bytes(bytes_we_know + bytes([j]))

            key = cryp.ecb_encryption_oracle_random_prefix(
                b'a' * bytes_amount + bytes(guess),
                unencrypted_string)[ignore_bytes:ignore_bytes + cipher_length]

            dictionary[key] = guess

        saved_byte = cryp.ecb_encryption_oracle_random_prefix(
            b'a' * bytes_amount + known_bytes[0:offset],
            unencrypted_string)[ignore_bytes + block:ignore_bytes + block +
                                cipher_length]
        if saved_byte in dictionary:
            correct_byte = dictionary[saved_byte][-1]
            known_bytes.append(correct_byte)
            decrypted_bytes += bytes([correct_byte])

        print(known_bytes)

import ipdb
ipdb.set_trace()
