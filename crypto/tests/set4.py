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

    def test_set_4_problem_26(self):
        c = self.crypto_kit

        attack_string = 'AAA admin true'
        result = c.pend_attack_ctr(attack_string)
        decrypted = c.ctr_encrypt(plain_text=result)

        first_change_index = decrypted.index(32)
        result_arr = bytearray(result)
        result_arr[first_change_index] = bytes(
            [result_arr[first_change_index] ^ 32 ^ 59])[0]
        decrypted = c.ctr_encrypt(plain_text=bytes(result_arr))

        second_change_index = decrypted.index(32)
        result_arr[second_change_index] = bytes(
            [result_arr[second_change_index] ^ 32 ^ 61])[0]
        decrypted = c.ctr_encrypt(plain_text=bytes(result_arr))
        self.assertEqual(b';admin=true' in decrypted, True)

    def test_set_4_problem_27(self):
        c = self.crypto_kit
        key = c.generate_random_bytes(16)

        message = b'A' * 16 + b'B' * 16 + b'C' * 16
        encrypted = c.cbc_encrypt(key, key, message)
        split = list(c.chunked(16, encrypted))
        mutated = b'' + split[0] + bytes([0] * 16) + split[0]

        decrypted = c.cbc_decrypt(key, key, mutated)

        def verify_ascii_compilance(plain_text):
            if not all(i < 128 for i in plain_text):
                return "invalid characters", plain_text

        verification = verify_ascii_compilance(decrypted)

        self.assertEqual(
            c.fixed_xor(verification[1][:16], verification[1][-16:]), key)

        return
