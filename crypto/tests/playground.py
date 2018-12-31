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

c = Crypto_Kit()
now = datetime.datetime.now()
now = int(time.mktime(now.timetuple()))
original_seed = now & 0xFFFF
known_text = c.generate_random_bytes(randint(5, 30)) + bytes([b'A' [0]] * 14)
encrypted = c.prng_ctr_encrypt(key=original_seed, plain_text=known_text)

padding = len(encrypted) - len(known_text)
known_text = bytes([0] * padding) + known_text
current_time = datetime.datetime.now()
current_time = int(time.mktime(current_time.timetuple()))

for i in range(1000):
    print("**********i", i)
    random_bytes = b''
    guess_seed = current_time - i & 0xFFFF
    prng = MT19937(guess_seed)
    while len(random_bytes) < len(encrypted):
        random_bytes += struct.pack("<L", prng.rand())

    result = c.fixed_xor(known_text, random_bytes[:len(known_text)])
    if encrypted[padding:] == result[padding:]:
        break
