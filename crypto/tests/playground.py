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

with open('./tests/25.txt', 'r') as myfile:
    base_64_text = myfile.read()
encrypted_text = cry.decode_base64(base_64_text)
random_key = bytes([randint(0, 255) for i in range(16)])
plain_text = cry.ecb_decrypt(b"YELLOW SUBMARINE", encrypted_text)
encrypted = cry.ctr_encrypt(random_key, 0, plain_text)
decrypted_text = b''

new_text = bytes([0] * len(encrypted))
key_stream = cry.edit(encrypted, random_key, 0, new_text)

import ipdb
ipdb.set_trace()
