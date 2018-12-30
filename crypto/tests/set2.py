import array
import unittest
import math
import datetime
import time
from crypto.crypto_tools import Crypto_Kit
from crypto.mt19937 import MT19937
from Crypto.Cipher import AES
from random import randint


class Set2(unittest.TestCase):
    def setUp(self):
        self.crypto_kit = Crypto_Kit()

    def test_set_2_problem_9(self):
        c = self.crypto_kit
        pad_result = c.pad_to_length(b"YELLOW SUBMARINE", 20)
        self.assertEqual(pad_result, b"YELLOW SUBMARINE\x04\x04\x04\x04")

    def test_set_2_problem_10(self):
        with open('./tests/10.txt', 'r') as myfile:
            encrypted_base_64 = myfile.read()
        c = self.crypto_kit
        encrypted_bytes = c.decode_base64(encrypted_base_64)
        iv = bytes([0] * 16)
        key = b"YELLOW SUBMARINE"

        self.assertEqual(
            c.cbc_decrypt(key, iv, encrypted_bytes),
            b"""I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"""
        )

    def test_set_2_problem_11(self):
        with open('./tests/10.txt', 'r') as myfile:
            encrypted_base_64 = myfile.read()
        c = self.crypto_kit
        encrypted_bytes = c.decode_base64(encrypted_base_64)
        self.assertEqual(
            self.crypto_kit.detect_cipher_mode(encrypted_bytes), 'cbc')

    def test_set_2_problem_12(self):
        c = self.crypto_kit
        unknown_string = """
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
            YnkK
        """

        unencrypted_string = c.decode_base64(unknown_string)

        cipher_length = c.get_ecb_cipher_length(unencrypted_string)

        mode = c.detect_cipher_mode(
            c.ecb_encryption_oracle(
                bytes([0] * cipher_length * 2), unencrypted_string))

        known_bytes = bytearray(bytes([0] * 15))

        chunks = list(c.chunked(cipher_length, unencrypted_string))
        decrypted_bytes = b''

        for chunk in range(len(chunks)):
            block = chunk * cipher_length

            for i in range(cipher_length):
                dictionary = {}
                offset = cipher_length - 1 - i
                bytes_we_know = bytes(known_bytes[-(cipher_length - 1):])
                for j in range(256):
                    guess = bytes(bytes_we_know + bytes([j]))

                    key = c.ecb_encryption_oracle(
                        bytes(guess), unencrypted_string)[0:cipher_length]

                    dictionary[key] = guess

                saved_byte = c.ecb_encryption_oracle(
                    known_bytes[0:offset],
                    unencrypted_string)[block:block + cipher_length]

                if saved_byte in dictionary:
                    correct_byte = dictionary[saved_byte][-1]
                    known_bytes.append(correct_byte)
                    decrypted_bytes += bytes([correct_byte])

        self.assertEqual(
            decrypted_bytes,
            b"""Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\x01"""
        )

    def test_set_2_problem_13(self):
        c = self.crypto_kit

        def get_cipher_length():
            profile = c.profile_for("a")
            length = len(profile)
            for i in range(100):
                result = c.profile_for("a" * i)
                if len(result) != length:
                    return len(result) - length

        cipher_length = get_cipher_length()

        need_bytes = b'email=&uid=10&role='
        email_length = math.ceil(
            len(need_bytes) / cipher_length) * cipher_length - len(need_bytes)

        email = "a" * email_length
        first_half_encrypted = c.profile_for(email)[0:len(need_bytes) +
                                                    email_length]
        admin_padding = cipher_length - len(b'admin')
        second_half_decrypted = (
            b'admin' + bytes([admin_padding] * admin_padding)).decode('utf-8')

        def isolate_block():
            for i in range(100):
                if c.dup_block_counts(c.profile_for("a" * i)) > 0:
                    return i

        second_half_encrypted = c.profile_for(
            "a" * (isolate_block() - 16) +
            second_half_decrypted)[32:32 + cipher_length]

        self.assertEqual(
            c.decrypt_profile(first_half_encrypted + second_half_encrypted),
            b'email=aaaaaaaaaaaaa&uid=10&role=admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
        )

    def test_set_2_problem_14(self):
        c = self.crypto_kit
        unknown_string = """
            Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
            YnkK
        """

        unencrypted_string = c.decode_base64(unknown_string)

        def get_unknown_bytes():
            for i in range(100):
                result = c.ecb_encryption_oracle_random_prefix(
                    b'a' * i, unencrypted_string)
                byte_set = set()
                prefix_bytes = b''
                split_bytes = list(c.chunked(16, result))
                for byte in split_bytes:
                    if byte in byte_set:
                        return result, i, len(prefix_bytes)
                    prefix_bytes += byte
                    byte_set.add(byte)

        cipher_length = 16
        result, bytes_amount, ignore_bytes = get_unknown_bytes()
        bytes_amount -= 16
        known_bytes = bytearray(bytes([0] * 15))

        chunks = list(c.chunked(cipher_length, result[ignore_bytes:]))
        decrypted_bytes = b''

        for chunk in range(len(chunks)):
            block = chunk * cipher_length

            for i in range(cipher_length):
                dictionary = {}
                offset = cipher_length - 1 - i
                bytes_we_know = bytes(known_bytes[-(cipher_length - 1):])
                for j in range(256):
                    guess = bytes(bytes_we_know + bytes([j]))

                    key = c.ecb_encryption_oracle_random_prefix(
                        b'a' * bytes_amount + bytes(guess),
                        unencrypted_string)[ignore_bytes:ignore_bytes +
                                            cipher_length]

                    dictionary[key] = guess

                saved_byte = c.ecb_encryption_oracle_random_prefix(
                    b'a' * bytes_amount + known_bytes[0:offset],
                    unencrypted_string)[ignore_bytes + block:ignore_bytes +
                                        block + cipher_length]
                if saved_byte in dictionary:
                    correct_byte = dictionary[saved_byte][-1]
                    known_bytes.append(correct_byte)
                    decrypted_bytes += bytes([correct_byte])

                print(known_bytes)

        self.assertEqual(
            decrypted_bytes,
            b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n\x01"
        )

    def test_set_2_problem_15(self):
        c = self.crypto_kit
        self.assertEqual(
            c.validate_pkcs_7(b"ICE ICE BABY\x04\x04\x04\x04"),
            b"ICE ICE BABY")
        self.assertEqual(
            c.validate_pkcs_7(b"ICE ICE BABY\x05\x05\x05\x05"), False)
        self.assertEqual(
            c.validate_pkcs_7(b"ICE ICE BABY\x05\x05\x05\x05"), False)

    def test_set_2_problem_16(self):
        c = self.crypto_kit
        attack_string = 'AAA admin true'
        result = c.pend_attack(attack_string)

        byte_array = bytearray(result)
        byte_array[19] = bytes([byte_array[19] ^ 59 ^ 32])[0]
        byte_array[25] = bytes([byte_array[25] ^ 61 ^ 32])[0]
        new_bytes = bytes(byte_array)

        self.assertEqual(c.is_admin(new_bytes), True)
