# Script for generating intermediate inversion problems for SHA-1

script_name="gen_weakM_cnfs.sh"
version=0.0.3

#if [ $# -eq 0 ]; then
#    >&2 echo "${script_name} number-of-rounds" 
#    exit 1
#fi

#rnd=$1

rnd=28
#echo "md5, rnd=${rnd}"
#for i in {1..31}
#do
#    echo "i=$i"
#    # 1-hash
#    hval=1
#    ./main --cnf --hash-function=md5 --rounds=${rnd} --hash-bits=128 --hash-value=${hval} --attack=preimage --equal-toM-bits=${i} --seed=0 > md5_preimage_${rnd}r_${i}bitM_${hval}hash.cnf
#    # 0-hash
#    hval=0
#    ./main --cnf --hash-function=md5 --rounds=${rnd} --hash-bits=128 --hash-value=${hval} --attack=preimage --equal-toM-bits=${i} --seed=0 > md5_preimage_${rnd}r_${i}bitM_${hval}hash.cnf
#    # random:
#    for j in {0..7}
#    do
#	echo "  j=$j"
#	./main --cnf --hash-function=md5 --rounds=${rnd} --hash-bits=128 --attack=preimage --equal-toM-bits=${i} --message-file=./random_messages/random_message_${j} > md5_preimage_${rnd}r_${i}bitM_randomhash${j}.cnf
#    done
#done

rnd=25
echo "sha1, rnd=${rnd}"
for i in {1..31}
do
    echo "i=$i"
    # 1-hash
    hval=1
    ./main --cnf --hash-function=sha1 --rounds=${rnd} --hash-bits=160 --hash-value=${hval} --attack=preimage --equal-toM-bits=${i} --seed=0 > sha1_preimage_${rnd}r_${i}bitM_${hval}hash.cnf
    # 0-hash
    hval=0
    ./main --cnf --hash-function=sha1 --rounds=${rnd} --hash-bits=160 --hash-value=${hval} --attack=preimage --equal-toM-bits=${i} --seed=0 > sha1_preimage_${rnd}r_${i}bitM_${hval}hash.cnf
    # random:
    for j in {0..7}
    do
	echo "  j=$j"
	./main --cnf --hash-function=sha1 --rounds=${rnd} --hash-bits=160 --attack=preimage --equal-toM-bits=${i} --message-file=./random_messages/random_message_${j} > sha1_preimage_${rnd}r_${i}bitM_randomhash${j}.cnf
    done
done
