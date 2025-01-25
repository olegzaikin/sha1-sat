# Script for generating intermediate inverse problems for MD5 and SHA-1

script_name="gen_weakM_cnfs.sh"
version="0.0.4"

cd ./scripts/
python3 ./gen_random_hashes.py
mv hashes_256bit.txt ..
cd ..
ln -s ../EnCnC/scripts/gen_hash_preimage_instances.py .

for rnd in {27..29}
do
    echo "md5, rnd=${rnd}"
    for i in {1..31}
    do
        echo "i=$i"
        # Generate a template CNF:
        ./main --cnf --hash-function=md5 --rounds=${rnd} --hash-value=0 --hash-bits=0 --attack=preimage --equal-toM-bits=${i} --seed=0 --compact-interm-enc > nossum_md5_preimage_${rnd}r_${i}bitM_template.cnf
        # Generate instances by adding hashes to the template CNF:
        python3 ./gen_hash_preimage_instances.py ./nossum_md5_preimage_${rnd}r_${i}bitM_template.cnf hashes_256bit.txt 128 10 --hashvars=./vars_nossum_md5 --random
    done
    mkdir cnfs_nossum_md5_${rnd}r_10hashes_interm_new
    mv nossum_md5_preimage_${rnd}r_*_hashlen* ./cnfs_nossum_md5_${rnd}r_10hashes_interm_new/
    rm *_template.cnf
done

for rnd in {22..23}
do
    echo "sha1, rnd=${rnd}"
    for i in {1..31}
    do
        echo "i=$i"
        # Generate a template CNF:
        ./main --cnf --hash-function=sha1 --rounds=${rnd} --hash-value=0 --hash-bits=0 --attack=preimage --equal-toM-bits=${i} --seed=0 --compact-interm-enc > nossum_sha1_preimage_${rnd}r_${i}bitM_template.cnf
        # Generate instances by adding hashes to the template CNF:
        python3 ./gen_hash_preimage_instances.py ./nossum_sha1_preimage_${rnd}r_${i}bitM_template.cnf hashes_256bit.txt 160 10 --hashvars=./vars_nossum_sha1-${rnd}r --random
    done
    mkdir cnfs_nossum_sha1_${rnd}r_10hashes_interm_new
    mv nossum_sha1_preimage_${rnd}r_*_hashlen* ./cnfs_nossum_sha1_${rnd}r_10hashes_interm_new/
    rm *_template.cnf
done
