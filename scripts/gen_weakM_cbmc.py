# Created on: 10 Aug 2024
# Author: Oleg Zaikin
# E-mail: zaikin.icc@gmail.com
#
# Generates CNFs for preimage attacks of step-reduced compression functions,
# where the last step is weakened as in
#   Oleg Zaikin. Inverting Step-reduced SHA-1 and MD5 by Parameterized SAT
#   Solvers. In CP 2024.
#==============================================================================

import sys

script_name = 'gen_weakM_cbmc.py'
version = '0.0.1'

if len(sys.argv) != 2 or (len(sys.argv) == 2 and sys.argv[1] == '-h'):
  sys.exit('Usage : ' + script_name + ' CBMC-input-file')

sourcefname = sys.argv[1]

print('Running script ' + script_name + ' of version ' + version)
print('CBMC input file : ' + sourcefname)

rounds = 0
assert('md5' in sourcefname)
if '28' in sourcefname:
  rounds = 28
elif '29' in sourcefname:
  rounds = 29
assert(rounds > 0)
print(str(rounds) + ' rounds')

before_lines = []
after_lines = []

with open(sourcefname, 'r') as f:
  lines = f.read().splitlines()
  is_after = False
  for line in lines:
    if 'int j = 1; // line for changing' in line:
      is_after = True
    elif is_after == False:
      before_lines.append(line)
    else:
      after_lines.append(line)

base_name_1 = 'cbmc_md5_' + str(rounds) + 'r_1hash_'
base_name_2 = 'bitM.c'
for j in range(1, 32):
  fname = base_name_1 + str(j) + base_name_2
  with open(fname, 'w') as f:
    for line in before_lines:
      f.write(line + '\n')
    f.write('  int j = ' + str(j) + ';\n')
    for line in after_lines:
      f.write(line + '\n')
