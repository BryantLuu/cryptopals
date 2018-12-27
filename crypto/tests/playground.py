import sys
import array
import math
from crypto.crypto_tools import Crypto_Kit
from Crypto.Cipher import AES
from random import randint

cryp = Crypto_Kit()
encrypted_bytes = cryp.decode_base64(
    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
print(cryp.ctr_encrypt("YELLOW SUBMARINE", 0, encrypted_bytes))
