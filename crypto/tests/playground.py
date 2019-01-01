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
key = cry.generate_random_bytes(16)

message = b'A' * 16 + b'B' * 16 + b'C' * 16
encrypted = cry.cbc_encrypt(key, key, message)
split = list(cry.chunked(16, encrypted))
mutated = b'' + split[0] + bytes([0] * 16) + split[0]

decrypted = cry.cbc_decrypt(key, key, mutated)


def verify_ascii_compilance(plain_text):
    if not all(i < 128 for i in plain_text):
        return "invalid characters", plain_text


verification = verify_ascii_compilance(decrypted)

import ipdb
ipdb.set_trace()
