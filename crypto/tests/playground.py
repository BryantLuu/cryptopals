import sys
import array
import math
from crypto.crypto_tools import Crypto_Kit
from Crypto.Cipher import AES
from random import randint

cryp = Crypto_Kit()
encrypted_bytes, iv = cryp.get_random_cbc_encrypted_string()
chunked_bytes = list(cryp.chunked(16, encrypted_bytes))

answer = b''

block = iv[0:]
plain_text = bytearray([0] * 16)
for target in reversed(range(len(block))):
    pad_length = len(block) - target
    poisoned_bytes = bytearray([0] * 16)
    padding_bytes = bytes([0] * target) + bytes([pad_length] * pad_length)
    for k in range(0, 256):
        if pad_length == 1 and k == pad_length:
            continue
        poisoned_bytes[target] = k
        malformed_bytes = cryp.fixed_xor(block, plain_text)
        malformed_bytes = cryp.fixed_xor(malformed_bytes, poisoned_bytes)
        malformed_bytes = cryp.fixed_xor(malformed_bytes, padding_bytes)
        valid_padding = cryp.decrypt_with_padding(chunked_bytes[0],
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
        padding_bytes = bytes([0] * target) + bytes([pad_length] * pad_length)
        for k in range(0, 256):
            if pad_length == 1 and k == pad_length:
                continue
            poisoned_bytes[target] = k
            malformed_bytes = cryp.fixed_xor(block, plain_text)
            malformed_bytes = cryp.fixed_xor(malformed_bytes, poisoned_bytes)
            malformed_bytes = cryp.fixed_xor(malformed_bytes, padding_bytes)
            malformed_cipher = b''.join(
                chunked_bytes[0:i]) + malformed_bytes + chunked_bytes[i + 1]

            valid_padding = cryp.decrypt_with_padding(malformed_cipher, iv)
            if valid_padding:
                plain_text[target] = bytes([k])[0]
                break
    answer += bytes(plain_text)
