import sys
import array
import unittest
from crypto.crypto_tools import Crypto_Kit

class TestClass(unittest.TestCase):
    def setUp(self):
        self.crypto_kit = Crypto_Kit()


    def test_set_1_problem_1(self):
        self.assertEqual(
            self.crypto_kit.hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        )


    def test_set_1_problem_2(self):
        c = self.crypto_kit
        self.assertEqual(
            c.fixed_xor(c.decode_hex("1c0111001f010100061a024b53535009181c"), c.decode_hex("686974207468652062756c6c277320657965")),
            c.decode_hex("746865206b696420646f6e277420706c6179")
        )


    def test_set_1_problem_3(self):
        c = self.crypto_kit
        encrypted_result = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        self.assertEqual(c.most_likely_stanza(c.decode_hex(encrypted_result))[1], b"Cooking MC's like a pound of bacon")


    def test_set_1_problem_4(self):
        c = self.crypto_kit
        with open('./tests/4.txt', 'r') as myfile:
            encrypted_result=myfile.read().splitlines()

        best_score = 0
        best_stanza = ""

        for line in encrypted_result:
            score, stanza, _ = c.most_likely_stanza(c.decode_hex(line))
            if score > best_score:
                best_score = score
                best_stanza = stanza

        self.assertEqual(best_stanza, b'Now that the party is jumping\n')


    def test_set_1_problem_5(self):
        c = self.crypto_kit
        result = c.repeating_xor(bytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", 'utf-8'),
            bytes("ICE", 'utf-8')
        )

        self.assertEqual(
            c.encode_hex(result),
            b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
        )

    def test_set_1_problem_6(self):
        c = self.crypto_kit
        with open('./tests/6.txt', 'r') as myfile:
            encrypted_result=myfile.read()

        encrypted_bytes = c.decode_base64(encrypted_result)
        key_length = c.find_key_length(encrypted_bytes)
        bytes_sections = list(c.chunked(key_length, encrypted_bytes))
        transposed = [*zip(*bytes_sections[0:-1])]
        keys = []
        for section in transposed:
            bytes_string = array.array('B', section).tobytes()
            _, _, single_key = c.most_likely_stanza(bytes_string)
            keys.append(single_key[0])

        decrypt_key = bytes(keys)
        decrypted_bytes = c.repeating_xor(encrypted_bytes, decrypt_key)

        self.assertEqual(
            decrypted_bytes,
            b"""I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"""
        )


    def test_set_1_problem_7(self):
        return
