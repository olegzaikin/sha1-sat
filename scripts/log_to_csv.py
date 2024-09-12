# Created on:24 August 2024
# Author: Oleg Zaikin
# E-mail: zaikin.icc@gmail.com
#
# Given log files with a solver's runtimes, form the csv-file.
#
# Example:
#   python3 ./log_to_csv.py kissat3.1.1 MD5
#==============================================================================

import sys
import glob, os

script_name = "log_to_csv.py"
version = "0.0.2"

if len(sys.argv) == 2 and sys.argv[1] == '-v':
    print('Script ' + script_name + ' of version : ' + version)
    exit(1)

if len(sys.argv) < 3 or (len(sys.argv) == 2 and sys.argv[1] == '-h'):
    print('Usage: ' + script_name + ' solver-name hash-funct')
    exit(1)

solver = sys.argv[1]
print('solver: ' + solver)

hash_funct = sys.argv[2]
print('hash_funct: ' + hash_funct)

os.chdir("./")
log_files = []
for file in glob.glob(solver + '_*' + hash_funct + '_log'):
    log_files.append(file)

assert(len(log_files) > 0)

print('solver log-files:')
for fname in log_files:
    print(fname)

instances_runtimes = dict()
func_name = ''

for fname in log_files:
    print('Reading ' + fname)
    with open(fname, 'r') as f:
        lines = f.read().splitlines()
        for line in lines:
            #print(line)
            words = line.split()
            index = -1
            mod_inst_name = ''
            if 'transalg' in words[1]:
                index = 0
                mod_inst_name = words[1].replace('transalg_', '')
            elif 'cbmc' in words[1]:
                index = 1
                mod_inst_name = words[1].replace('cbmc_', '')
            elif 'nossum' in words[1]:
                index = 2
                mod_inst_name = words[1].replace('nossum_', '')
            assert(index >= 0)
            inst_words = mod_inst_name.split('_')
            func_name = inst_words[0].lower()
            mod_inst_name = func_name + '_' + inst_words[1] + '_' + inst_words[2] + '_' + inst_words[-2] + '_' + inst_words[-1]
            print(mod_inst_name)
            rt = float(words[2])
            print('index : ' + str(index))
            print('runtime : ' + str(rt))
            if mod_inst_name not in instances_runtimes:
                runtimes = [-1, -1, -1]
                runtimes[index] = rt
                instances_runtimes[mod_inst_name] = runtimes
            else:
                instances_runtimes[mod_inst_name][index] = rt

ofname = func_name + '_' + solver + '.csv'
print('Writing to ' + ofname)
with open(ofname, 'w') as ofile:
    ofile.write('instance ' + solver + '-transalg ' + solver + '-cbmc ' + solver + '-nossum\n')
    for inst in instances_runtimes:
        ofile.write(inst)
        for rt in instances_runtimes[inst]:
            assert(rt != -1)
            ofile.write(' ' + str(rt))
        ofile.write('\n')
