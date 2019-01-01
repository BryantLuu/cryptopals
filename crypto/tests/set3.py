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


class Set3(unittest.TestCase):
    def setUp(self):
        self.crypto_kit = Crypto_Kit()

    def test_set_3_problem_17(self):
        c = self.crypto_kit
        encrypted_bytes, iv = c.get_random_cbc_encrypted_string()
        chunked_bytes = list(c.chunked(16, encrypted_bytes))

        answer = b''

        block = iv[0:]
        plain_text = bytearray([0] * 16)
        for target in reversed(range(len(block))):
            pad_length = len(block) - target
            poisoned_bytes = bytearray([0] * 16)
            padding_bytes = bytes([0] * target) + bytes(
                [pad_length] * pad_length)
            for k in range(0, 256):
                if pad_length == 1 and k == pad_length:
                    continue
                poisoned_bytes[target] = k
                malformed_bytes = c.fixed_xor(block, plain_text)
                malformed_bytes = c.fixed_xor(malformed_bytes, poisoned_bytes)
                malformed_bytes = c.fixed_xor(malformed_bytes, padding_bytes)
                valid_padding = c.decrypt_with_padding(chunked_bytes[0],
                                                       malformed_bytes)
                if valid_padding:
                    plain_text[target] = bytes([k])[0]
                    break
        answer += bytes(plain_text)

        for i in range(len(chunked_bytes) - 1):
            block = chunked_bytes[i]
            plain_text = bytearray([0] * 16)

            for target in reversed(range(len(block))):
                pad_length = len(block) - target
                poisoned_bytes = bytearray([0] * 16)
                padding_bytes = bytes([0] * target) + bytes(
                    [pad_length] * pad_length)
                for k in range(0, 256):
                    if pad_length == 1 and k == pad_length:
                        continue
                    poisoned_bytes[target] = k
                    malformed_bytes = c.fixed_xor(block, plain_text)
                    malformed_bytes = c.fixed_xor(malformed_bytes,
                                                  poisoned_bytes)
                    malformed_bytes = c.fixed_xor(malformed_bytes,
                                                  padding_bytes)
                    malformed_cipher = b''.join(
                        chunked_bytes[0:i]) + malformed_bytes + chunked_bytes[
                            i + 1]

                    valid_padding = c.decrypt_with_padding(
                        malformed_cipher, iv)
                    if valid_padding:
                        plain_text[target] = bytes([k])[0]
                        break
            answer += bytes(plain_text)

        decrypted = c.cbc_decrypt(iv=iv, encrypted_bytes=encrypted_bytes)
        print('****decrypted', decrypted)
        self.assertEqual(decrypted, answer)

    def test_set_3_problem_18(self):
        c = self.crypto_kit
        encrypted_bytes = c.decode_base64(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
        )
        self.assertEqual(
            c.ctr_encrypt(b"YELLOW SUBMARINE", 0, encrypted_bytes),
            b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")

    def test_set_3_problem_19(self):
        c = self.crypto_kit
        with open('./tests/19.txt', 'r') as myfile:
            plain_encoded = myfile.read().splitlines()

        plain_texts = [c.decode_base64(result) for result in plain_encoded]

        encrypted_results = [
            c.ctr_encrypt(plain_text=plain_text) for plain_text in plain_texts
        ]

        key_stream = b''

        for i in range(len(encrypted_results[0])):
            max_score = 0
            key_stream_byte = b''
            for j in range(256):
                score = 0
                for line in encrypted_results:
                    if i < len(line):
                        possible_plain_byte = bytes([line[i] ^ j])
                        if possible_plain_byte:
                            possible_plain_text = possible_plain_byte[0]
                            if c.is_english_character(possible_plain_text):
                                score += c.letter_scores[chr(
                                    possible_plain_text).upper()]
                if score > max_score:
                    max_score = score
                    key_stream_byte = bytes([j])
            key_stream += key_stream_byte

        self.assertEqual(
            c.fixed_xor(encrypted_results[0].lower(),
                        key_stream).decode('utf-8').lower(),
            b'i have met them at close of day'.decode('utf-8'))

    def test_set_3_problem_20(self):
        c = self.crypto_kit
        with open('./tests/20.txt', 'r') as myfile:
            plain_encoded = myfile.read().splitlines()

        plain_texts = [c.decode_base64(result) for result in plain_encoded]

        encrypted_results = [
            c.ctr_encrypt(plain_text=plain_text) for plain_text in plain_texts
        ]

        min_length = len(encrypted_results[0])

        for encrypted in encrypted_results:
            if len(encrypted) < min_length:
                min_length = len(encrypted)

        truncated_results = [
            result[0:min_length] for result in encrypted_results
        ]

        bytes_sections = truncated_results
        transposed = [*zip(*bytes_sections)]
        keys = []
        for section in transposed:
            bytes_string = array.array('B', section).tobytes()
            _, _, single_key = c.most_likely_stanza(bytes_string)
            keys.append(single_key[0])

        decrypt_key = bytes(keys)
        self.assertEqual(
            c.fixed_xor(truncated_results[0], decrypt_key),
            b'N\'m rated "R"...this is a warning, ya better void / P')

    def test_set_3_problem_22(self):
        now = datetime.datetime.now()
        now = int(time.mktime(now.timetuple()))
        later = now + randint(40, 1000)
        even_later = later + randint(0, 1000)
        seed = later

        prng = MT19937(seed)
        first_num = prng.rand()

        for i in range(0, 1000):
            seed_guess = even_later - i
            if MT19937(seed_guess).rand() == first_num:
                break

        self.assertEqual(seed_guess, seed)

    def test_set_3_problem_23(self):
        c = self.crypto_kit
        seed = 12345678
        prng = MT19937(seed)

        state = []

        for i in range(624):
            num = prng.rand()
            state.append(c.untemper(num))

        clone = MT19937(0)
        clone.mt = state
        self.assertEqual(prng.rand(), clone.rand())

    def test_set_3_problem_24(self):
        c = self.crypto_kit
        now = datetime.datetime.now()
        now = int(time.mktime(now.timetuple()))
        original_seed = now & 0xFFFF
        known_text = c.generate_random_bytes(randint(5, 30)) + bytes(
            [b'A' [0]] * 14)
        encrypted = c.prng_ctr_encrypt(
            key=original_seed, plain_text=known_text)

        padding = len(encrypted) - len(known_text)
        known_text = bytes([0] * padding) + known_text
        current_time = datetime.datetime.now()
        current_time = int(time.mktime(current_time.timetuple()))

        for i in range(1000):
            random_bytes = b''
            guess_seed = current_time - i & 0xFFFF
            prng = MT19937(guess_seed)
            while len(random_bytes) < len(encrypted):
                random_bytes += struct.pack("<L", prng.rand())

            result = c.fixed_xor(known_text, random_bytes[:len(known_text)])
            if encrypted[padding:] == result[padding:]:
                break

        self.assertEqual(original_seed, guess_seed)
