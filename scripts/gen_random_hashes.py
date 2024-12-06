# Created on 26 August 2024
# Author: Oleg Zaikin
# E-mail: zaikin.icc@gmail.com
#
# Generate 10 256-bit hashes: 256 0s, 256 1s, and 8 random ones.
#
# Example:
#   python3 ./gen_random_hashes.py
#==============================================================================

import random

script_name = "gen_random_hashes.py"
version = "0.0.2"

random.seed(0)

random_strings = []
with open('hashes_256bit.txt', 'w') as ofile:
    ofile.write(('0'*256) + '\n')
    ofile.write(('1'*256) + '\n')
    for i in range(8):
        s = ''
        for j in range(256):
            s += str(random.randint(0, 1))
        random_strings.append(s)
        ofile.write(s + '\n')


hash_sizes = [128, 160, 256]
for hash_size in hash_sizes:
    print(str(hash_size) + '-bit random messages in hex:')
    for s in random_strings:
        print(str(hex(int(s[:hash_size], 2))))
    print('')
