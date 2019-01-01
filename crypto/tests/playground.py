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

attack_string = 'AAA admin true'
result = cry.pend_attack_ctr(attack_string)
decrypted = cry.ctr_encrypt(plain_text=result)

first_change_index = decrypted.index(32)
result_arr = bytearray(result)
result_arr[first_change_index] = bytes(
    [result_arr[first_change_index] ^ 32 ^ 59])[0]
decrypted = cry.ctr_encrypt(plain_text=bytes(result_arr))

second_change_index = decrypted.index(32)
result_arr[second_change_index] = bytes(
    [result_arr[second_change_index] ^ 32 ^ 61])[0]
decrypted = cry.ctr_encrypt(plain_text=bytes(result_arr))

import ipdb
ipdb.set_trace()
