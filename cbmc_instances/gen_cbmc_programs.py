# Generate random instances for the SHA-1 preimage problem via CBMC

import sys

base_name = "../random_messages/random_message_"
first_part_lines_num = 140

if len(sys.argv) < 2:
  print('Usage: script cbmc-program-name')
  exit(1)

cbmc_program_name = sys.argv[1]
print('cbmc_program_name : ' + cbmc_program_name)

base_cbmc_program_name = cbmc_program_name.split('.c')[0] + '_randomhash'

lines = open(cbmc_program_name,'r').read().splitlines()

first_part_lines = []
second_part_lines = []
for line in lines[:first_part_lines_num+1]:
  first_part_lines.append(line)

for line in lines[first_part_lines_num:]:
  second_part_lines.append(line)

for i in range(8):
  random_message_file_name = base_name + str(i)
  random_lines = open(random_message_file_name,'r').read().splitlines()
  s = ''
  k = 0
  for line in random_lines:
    s += '  __CPROVER_assume(output1[' + str(k) + '] == ' + line + ');' + '\n'
    k += 1
  with open(base_cbmc_program_name + str(i) + '.c', 'w') as f:
    for line in first_part_lines:
      f.write(line + '\n')
    f.write(s)
    for line in second_part_lines:
      f.write(line + '\n')
  #print(s)
  #print(lines)
  #print('')

#__CPROVER_assume(output1[i] == 0);

#print(first_part_lines)
#print('###')
#print(second_part_lines)
