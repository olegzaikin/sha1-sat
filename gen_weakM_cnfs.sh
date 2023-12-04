# Script for generating intermediate inversion problems for SHA-1

script_name="gen_weakM_cnfs.sh"
version=0.0.2

if [ $# -eq 0 ]; then
    >&2 echo "${script_name} number-of-rounds" 
    exit 1
fi

rnd=$1
hval=1

for i in {1..31}
do
    echo $i
    ./main --cnf --rounds=${rnd} --hash-bits=160 --hash-value=${hval} --attack=preimage --equal-toM-bits=${i} --seed=0 > sha1_preimage_${rnd}r_${i}bitM_${havl}hash.cnf
done
