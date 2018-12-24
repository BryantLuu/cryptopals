import base64
import codecs
import math
from Crypto.Cipher import AES
from random import randint

global_random_key = bytes([randint(0, 255) for i in range(16)])


class Crypto_Kit():

    letter_scores = {
        ' ': 15,
        'E': 12.02,
        'T': 9.10,
        'A': 8.12,
        'O': 7.68,
        'I': 7.31,
        'N': 6.95,
        'S': 6.28,
        'R': 6.02,
        'H': 5.92,
        'D': 4.32,
        'L': 3.98,
        'U': 2.88,
        'C': 2.71,
        'M': 2.61,
        'F': 2.30,
        'Y': 2.11,
        'W': 2.09,
        'G': 2.03,
        'P': 1.82,
        'B': 1.49,
        'V': 1.11,
        'K': 0.69,
        'X': 0.17,
        'Q': 0.11,
        'J': 0.10,
        'Z': 0.07,
    }

    def hex_to_base64(self, hex_string):
        return codecs.decode(base64.b64encode(self.decode_hex(hex_string)))

    def decode_base64(self, base64_string):
        return base64.b64decode(base64_string)

    def decode_hex(self, hex_string):
        return codecs.decode(hex_string, 'hex')

    def encode_hex(self, bytes_string):
        return codecs.encode(bytes_string, 'hex')

    def fixed_xor(self, first_bytes, second_bytes):
        return bytes([a ^ b for a, b in zip(first_bytes, second_bytes)])

    def is_english_character(self, byte):
        if (byte >= 65 and byte <= 90) or (byte <= 122
                                           and byte >= 97) or byte == 32:
            return True
        return False

    def get_all_possible_hex(self):
        hex_array = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c',
            'd', 'e', 'f'
        ]
        possible_hexs = []
        for h in hex_array:
            for i in hex_array:
                possible_hexs.append(f"{h}{i}")
        return possible_hexs

    def score_phrase(self, stanza):
        score = 0
        for byte in stanza:
            if self.is_english_character(byte):
                score += self.letter_scores[chr(byte).upper()]
        return score

    def most_likely_stanza(self, bytes_stanza):
        possible_hexes = self.get_all_possible_hex()
        required_bytes_amount = int(len(bytes_stanza))

        max_score = 0
        stanza = ""
        decoded_hex = None
        for possible_hex in possible_hexes:
            result = self.fixed_xor(
                bytes_stanza,
                self.decode_hex((possible_hex * required_bytes_amount)))
            score = self.score_phrase(result)

            if score > max_score:
                max_score = score
                stanza = result
                decoded_hex = self.decode_hex(possible_hex)
        return max_score, stanza, decoded_hex

    def repeating_xor(self, bytes_stanza, encryption_key):
        required_bytes_amount = len(bytes_stanza)
        return bytes([
            bytes_stanza[index] ^ encryption_key[index % len(encryption_key)]
            for index in range(required_bytes_amount)
        ])

    def calculate_hamming_distance(self, first_string_bytes,
                                   second_string_bytes):
        count = 0
        for index in range(len(first_string_bytes)):
            first_bits = self.get_bits(first_string_bytes[index])
            second_bits = self.get_bits(second_string_bytes[index])
            while len(first_bits) < 8:
                first_bits = "0" + first_bits
            while len(second_bits) < 8:
                second_bits = "0" + second_bits
            for index2 in range(len(first_bits)):
                if first_bits[index2] != second_bits[index2]:
                    count += 1
        return count

    def get_bits(self, bytes_int_representation):
        return bin(bytes_int_representation).lstrip('0b')

    def find_key_length(self, encrypted_bytes):
        min_edit_distance = None
        key_length = 2
        possible_key_lengths = []
        for key_guess in range(2, 41):
            bytes_sections = list(self.chunked(key_guess, encrypted_bytes))
            edit_distance = self.calculate_hamming_distance(
                bytes_sections[0], bytes_sections[1])
            edit_distance += self.calculate_hamming_distance(
                bytes_sections[0], bytes_sections[2])
            edit_distance += self.calculate_hamming_distance(
                bytes_sections[0], bytes_sections[3])
            edit_distance += self.calculate_hamming_distance(
                bytes_sections[1], bytes_sections[2])
            edit_distance += self.calculate_hamming_distance(
                bytes_sections[1], bytes_sections[3])
            edit_distance += self.calculate_hamming_distance(
                bytes_sections[2], bytes_sections[3])
            edit_distance /= 6
            edit_distance /= key_guess

            possible_key_lengths.append((key_guess, edit_distance))

        return sorted(possible_key_lengths, key=lambda pair: pair[1])[0][0]

    def chunked(self, size, source):
        for i in range(0, len(source), size):
            yield source[i:i + size]

    def pad_to_length(self, bytes_string, length):
        pad_amount = length - len(bytes_string)
        return bytes_string + bytes([pad_amount] * pad_amount)

    def ecb_encrypt(self, key, plain_text):
        cipher = AES.new(key, AES.MODE_ECB)
        need_padding = math.ceil(
            len(plain_text) / len(key)) * len(key) - len(plain_text)
        padded_unencrypted_bytes = self.pad_to_length(
            plain_text,
            len(plain_text) + need_padding)
        encrypted_bytes = b''
        blocks = list(self.chunked(len(key), padded_unencrypted_bytes))
        for block in blocks:
            encrypted_bytes += cipher.encrypt(block)
        return encrypted_bytes

    def ecb_decrypt(self, key, encrypted_bytes):
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_bytes = b''
        blocks = list(self.chunked(len(key), encrypted_bytes))
        for block in blocks:
            decrypted_bytes += cipher.decrypt(block)
        return decrypted_bytes

    def cbc_decrypt(self, key, iv, encrypted_bytes):
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_bytes = b""
        blocks = list(self.chunked(len(key), encrypted_bytes))
        for block in blocks:
            decrypted_block = cipher.decrypt(block)
            decrypted_bytes += self.fixed_xor(decrypted_block, iv)
            iv = block
        return decrypted_bytes

    def cbc_encrypt(self, key, iv, unencrypted_bytes):
        cipher = AES.new(key, AES.MODE_ECB)
        need_padding = math.ceil(len(unencrypted_bytes) /
                                 len(key)) * len(key) - len(unencrypted_bytes)

        padded_unencrypted_bytes = self.pad_to_length(
            unencrypted_bytes,
            len(unencrypted_bytes) + need_padding)
        encrypted_bytes = b""
        blocks = list(self.chunked(len(key), padded_unencrypted_bytes))
        for block in blocks:
            encrypted_block = cipher.encrypt(self.fixed_xor(block, iv))
            encrypted_bytes += encrypted_block
            iv = encrypted_block
        return encrypted_bytes

    def generate_random_bytes(self, length):
        return bytes([randint(0, 255) for i in range(length)])

    def encryption_oracle(self, plain_text):
        plain_text = bytes(
            self.generate_random_bytes(randint(5, 10)) + plain_text +
            self.generate_random_bytes(randint(5, 10)))

        random_aes_key = self.generate_random_bytes(16)
        random_iv = self.generate_random_bytes(16)
        if randint(0, 1):
            print('ecb')
            return self.ecb_encrypt(random_aes_key, plain_text)
        else:
            print('cbc')
            return self.cbc_encrypt(random_aes_key, random_iv, plain_text)

    def detect_cipher_mode(self, encrypted_bytes):
        if self.dup_block_counts(encrypted_bytes) > 0:
            return 'ebc'
        return 'cbc'

    def dup_block_counts(self, encrypted_bytes):
        dupes = 0
        byte_set = set()
        split_bytes = list(self.chunked(16, encrypted_bytes))
        for byte in split_bytes:
            if byte in byte_set:
                dupes += 1
            byte_set.add(byte)
        return dupes

    def ecb_encryption_oracle(self, plain_text, unknown_string):
        global global_random_key
        plain_text = bytes(plain_text + unknown_string)
        return self.ecb_encrypt(global_random_key, plain_text)

    def get_ecb_cipher_length(self, encrypted_bytes):
        result = self.ecb_encryption_oracle(bytes([0]), encrypted_bytes)
        length = len(result)
        for i in range(100):
            oracle_result = self.ecb_encryption_oracle(
                bytes([0] * i), encrypted_bytes)

            if len(oracle_result) != length:
                return len(oracle_result) - length

    def parse_dict_values(self, text):
        pairs = text.split("&")
        return {k: v for k, v in [pair.split("=") for pair in pairs]}

    def profile_for(self, email):
        clean = email.replace("&", '')
        clean = clean.replace("=", '')

        profile = {'email': clean, 'uid': 10, 'role': 'user'}
        encoded = ''
        for key in profile:
            if encoded:
                encoded += '&'
            encoded += f'{key}={profile[key]}'
        global global_random_key
        encrypted = self.ecb_encrypt(global_random_key, bytes(
            encoded, 'utf-8'))
        return encrypted

    def decrypt_profile(self, profile):
        global global_random_key
        decrypted = self.ecb_decrypt(global_random_key, profile)
        return decrypted
