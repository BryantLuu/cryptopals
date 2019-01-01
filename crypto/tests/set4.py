import array
import unittest
import math
import datetime
import time
import struct
from crypto.crypto_tools import Crypto_Kit
from crypto.mt19937 import MT19937
from Crypto.Cipher import AES
from random import randint


class Set4(unittest.TestCase):
    def setUp(self):
        self.crypto_kit = Crypto_Kit()

    def test_set_4_problem_25(self):
        c = self.crypto_kit

        with open('./tests/25.txt', 'r') as myfile:
            base_64_text = myfile.read()
        encrypted_text = c.decode_base64(base_64_text)
        random_key = bytes([randint(0, 255) for i in range(16)])
        plain_text = c.ecb_decrypt(b"YELLOW SUBMARINE", encrypted_text)
        encrypted = c.ctr_encrypt(random_key, 0, plain_text)
        new_text = bytes([0] * len(encrypted))
        key_stream = c.edit(encrypted, random_key, 0, new_text)
        recovered_plain_text = c.fixed_xor(encrypted, key_stream)

        self.assertEqual(plain_text, recovered_plain_text)
