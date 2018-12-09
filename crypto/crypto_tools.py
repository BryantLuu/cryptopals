import base64
import codecs

class Crypto_Codec():
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


    def fixed_xor(self, first, second):
        return bytes([a ^ b for a, b in zip(self.decode_hex(first), self.decode_hex(second))])

    def is_english_character(self, letter):
        if (letter >= 65 and letter <= 90) or (letter <= 122 and letter >= 97) or letter == 32:
            return True
        return False

    def get_all_possible_hex(self):
        hex_array = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
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

    def most_likely_stanza(self, encrypted_result):
        possible_hexes = self.get_all_possible_hex()
        required_bytes_amount = int(len(encrypted_result)/2)

        stanza = ""
        max_score = 0
        for possible_hex in possible_hexes:
            result = self.fixed_xor(encrypted_result, possible_hex * required_bytes_amount)
            score = self.score_phrase(result)

            if score > max_score:
                max_score = score
                stanza = result
        return max_score, stanza

    def repeating_xor_encrypt(self, stanza, key):
        bytes_stanza = bytes(stanza, 'utf-8')
        encryption_key = bytes(key, 'utf-8')

        required_bytes_amount = len(bytes_stanza)
        return self.encode_hex(bytes([bytes_stanza[index] ^ encryption_key[index % len(encryption_key)] for index in range(required_bytes_amount)]))

    def calculate_hamming_distance(self, first_string_bytes, second_string_bytes):
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
        min_edit_distance = self.calculate_hamming_distance(encrypted_bytes[0:1], self.get_bits(encrypted_bytes[2:3]))
        key_length = 1
        for key_guess in range(2, 41):
            edit_distance = self.calculate_hamming_distance(encrypted_bytes[0:key_guess], encrypted_bytes[key_guess+1:key_guess+key_guess+1])
            key_guess = index + 1
            if edit_distance < min_edit_distance:
                key_length = key_guess
                min_edit_distance = edit_distance
