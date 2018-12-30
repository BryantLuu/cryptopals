import sys
import array
import math
import datetime
import time
from crypto.crypto_tools import Crypto_Kit
from crypto.mt19937 import MT19937
from Crypto.Cipher import AES
from random import randint


now = datetime.datetime.now()
now = int(time.mktime(now.timetuple()))
later = now + randint(40, 1000)
seed = later
even_later = later + randint(0, 1000)

prng = MT19937(seed)
first_num = prng.rand()

for i in range(0, 1000):
    seed_guess = even_later - i
    if MT19937(seed_guess).rand() == first_num:
        break

import ipdb; ipdb.set_trace()
