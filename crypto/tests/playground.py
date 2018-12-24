import sys
import array
import math
from crypto.crypto_tools import Crypto_Kit
from Crypto.Cipher import AES
from random import randint

cryp = Crypto_Kit()


def get_cipher_length():
    profile = cryp.profile_for("a")
    length = len(profile)
    for i in range(100):
        result = cryp.profile_for("a" * i)
        if len(result) != length:
            return len(result) - length


cipher_length = get_cipher_length()

need_bytes = b'email=&uid=10&role='
email_length = math.ceil(
    len(need_bytes) / cipher_length) * cipher_length - len(need_bytes)

email = "a" * email_length
first_half_encrypted = cryp.profile_for(email)[0:len(need_bytes) +
                                               email_length]
admin_padding = cipher_length - len(b'admin')
second_half_decrypted = (
    b'admin' + bytes([admin_padding] * admin_padding)).decode('utf-8')


def isolate_block():
    for i in range(100):
        if cryp.dup_block_counts(cryp.profile_for("a" * i)) > 0:
            return i


second_half_encrypted = cryp.profile_for("a" * (isolate_block() - 16) +
                                         second_half_decrypted)[32:32 +
                                                                cipher_length]

cryp.decrypt_profile(first_half_encrypted + second_half_encrypted)

import ipdb
ipdb.set_trace()
