set -e
set -u

g++ -Wall -std=c++0x -O2 -o main main.c -lboost_program_options
g++ -Wall -std=c++0x -O2 -o verify-preimage verify-preimage.c
