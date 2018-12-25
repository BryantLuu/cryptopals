import sys
import array
import math
from crypto.crypto_tools import Crypto_Kit
from Crypto.Cipher import AES
from random import randint

cryp = Crypto_Kit()
attack_string = 'AAAA admin true '
result = cryp.pend_attack(attack_string)

byte_array = bytearray(result)
byte_array[20] = bytes([byte_array[20] ^ 59 ^ 32])[0]
byte_array[26] = bytes([byte_array[26] ^ 61 ^ 32])[0]
byte_array[31] = bytes([byte_array[31] ^ 59 ^ 32])[0]
new_bytes = bytes(byte_array)

print(cryp.is_admin(new_bytes))

import ipdb
ipdb.set_trace()
