import sys
import unittest
from crypto.crypto_tools import Crypto_Codec

class TestClass(unittest.TestCase):
    def test_set_1_problem_1(self):
        self.assertEqual(
            Crypto_Codec().hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        )

    def test_set_1_problem_2(self):
        c = Crypto_Codec()
        self.assertEqual(
            c.fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"),
            c.decode_hex("746865206b696420646f6e277420706c6179")
        )

    def test_set_1_problem_3(self):
        c = Crypto_Codec()
        encrypted_result = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        self.assertEqual(c.most_likely_stanza(encrypted_result)[1], b"Cooking MC's like a pound of bacon")

    def test_set_1_problem_4(self):
        c = Crypto_Codec()
        with open('./tests/4.txt', 'r') as myfile:
            encrypted_result=myfile.read().splitlines()

        best_score = 0
        best_stanza = ""

        for line in encrypted_result:
            score, stanza = c.most_likely_stanza(line)
            if score > best_score:
                best_score = score
                best_stanza = stanza

        self.assertEqual(best_stanza, b'Now that the party is jumping\n')

    def test_set_1_problem_5(self):
        c = Crypto_Codec()
        result = c.repeating_xor_encrypt("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
            "ICE"
        )

        self.assertEqual(
            result,
            b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
        )

    def test_set_1_problem_6(self):
        c = Crypto_Codec()
        with open('./tests/6.txt', 'r') as myfile:
            encrypted_result=myfile.read()
        encrypted_bytes = c.decode_base64(encrypted_result)
        key_length = c.find_key_length(encrypted_bytes)
        print("*******key_length", key_length)


        self.assertEqual(
            1,
            2
        )
