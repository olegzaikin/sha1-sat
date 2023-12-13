# Generate 512-bit random messages,
# each as 16 32-bit random unsigned integer.

import random

message_num = 8
message_size = 512 # in bits
words_num = 16
max_value = pow(2,32) - 1

#print('Max 32-bit word value : ' + str(max_value))

random.seed(0)
for i in range(message_num):
  #print('message ' + str(i) + ':')
  s = ''
  for j in range(words_num):
    rand_uint = random.randrange(max_value)
    s += str(rand_uint) + '\n'
  with open('random_message_' + str(i), 'w') as f:
    f.write(s)
