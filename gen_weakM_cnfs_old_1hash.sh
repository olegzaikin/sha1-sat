rnd=27
echo "md5, rnd=${rnd}"
for i in {1..31}
do
    echo "i=$i"
    # 1-hash
    hval=1
    ./main --cnf --hash-function=md5 --rounds=${rnd} --hash-bits=128 --hash-value=${hval} --attack=preimage --equal-toM-bits=${i} --seed=0 > md5_preimage_${rnd}r_${i}bitM_${hval}hash_old.cnf
done

rnd=28
echo "md5, rnd=${rnd}"
for i in {1..31}
do
    echo "i=$i"
    # 1-hash
    hval=1
    ./main --cnf --hash-function=md5 --rounds=${rnd} --hash-bits=128 --hash-value=${hval} --attack=preimage --equal-toM-bits=${i} --seed=0 > md5_preimage_${rnd}r_${i}bitM_${hval}hash_old.cnf
done

rnd=29
echo "md5, rnd=${rnd}"
for i in {1..31}
do
    echo "i=$i"
    # 1-hash
    hval=1
    ./main --cnf --hash-function=md5 --rounds=${rnd} --hash-bits=128 --hash-value=${hval} --attack=preimage --equal-toM-bits=${i} --seed=0 > md5_preimage_${rnd}r_${i}bitM_${hval}hash_old.cnf
done

for rnd in {27..29}
do
    mkdir -p cnfs_nossum_md5_${rnd}r_1hash_interm_old/
    mv *md5*${rnd}r*.cnf ./cnfs_nossum_md5_${rnd}r_1hash_interm_old/
done
