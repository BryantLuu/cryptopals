import sys
import array
import math
from crypto.crypto_tools import Crypto_Kit
from Crypto.Cipher import AES
from random import randint

cryp = Crypto_Kit()
with open('./tests/19.txt', 'r') as myfile:
    plain_encoded = myfile.read().splitlines()

plain_texts = [cryp.decode_base64(result) for result in plain_encoded]

encrypted_results = [
    cryp.ctr_encrypt(plain_text=plain_text) for plain_text in plain_texts
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
                    if cryp.is_english_character(possible_plain_text):
                        score += cryp.letter_scores[chr(possible_plain_text).
                                                    upper()]
        if score > max_score:
            max_score = score
            key_stream_byte = bytes([j])
    key_stream += key_stream_byte

import ipdb
ipdb.set_trace()
