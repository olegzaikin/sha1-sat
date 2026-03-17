# Script for generating inverse problems for MD5 and SHA-1

script_name="gen_cnfs.sh"
version="0.0.2"

cd ./scripts/
python3 ./gen_random_hashes.py
mv hashes_256bit.txt ..
cd ..
ln -s ./scripts/gen_hash_preimage_instances.py .

# MD5:
for rnd in {27..30}
do
    echo "md5, rnd=${rnd}"
    #./main --cnf --rounds=${rnd} --hash-bits=128 --hash-value=0 --attack=preimage --seed=0 --hash-function=md5 > nossum_md5_preimage_${rnd}r_0hash.cnf
    #./main --cnf --rounds=${rnd} --hash-bits=128 --hash-value=1 --attack=preimage --seed=0 --hash-function=md5 > nossum_md5_preimage_${rnd}r_1hash.cnf
    # Generate a template CNF:
    ./main --cnf --hash-function=md5 --rounds=${rnd} --hash-value=0 --hash-bits=0 --attack=preimage --seed=0 > nossum_md5_preimage_${rnd}r_template.cnf
    # Generate instances by adding hashes to the template CNF:
    python3 ./gen_hash_preimage_instances.py ./nossum_md5_preimage_${rnd}r_template.cnf hashes_256bit.txt 128 10 --hashvars=./vars_nossum_md5 --random
done

rm -r cnfs_nossum_md5_10hashes
mkdir cnfs_nossum_md5_10hashes
mv nossum_md5*hashlen*.cnf ./cnfs_nossum_md5_10hashes
mv nossum_md5*r_0hash.cnf ./cnfs_nossum_md5_10hashes
mv nossum_md5*r_1hash.cnf ./cnfs_nossum_md5_10hashes

# SHA-1:
for rnd in {21..25}
do
    echo "sha-1, rnd=${rnd}"
    #./main --cnf --rounds=${rnd} --hash-bits=160 --hash-value=0 --attack=preimage --seed=0 --hash-function=sha1 > nossum_sha1_preimage_${rnd}r_0hash.cnf
    #./main --cnf --rounds=${rnd} --hash-bits=160 --hash-value=1 --attack=preimage --seed=0 --hash-function=sha1 > nossum_sha1_preimage_${rnd}r_1hash.cnf
    # Generate a template CNF:
    ./main --cnf --hash-function=sha1 --rounds=${rnd} --hash-value=0 --hash-bits=0 --attack=preimage --seed=0 > nossum_sha1_preimage_${rnd}r_template.cnf
    # Generate instances by adding hashes to the template CNF:
    python3 ./gen_hash_preimage_instances.py ./nossum_sha1_preimage_${rnd}r_template.cnf hashes_256bit.txt 160 10 --hashvars=./vars_nossum_sha1-${rnd}r --random
done

rm -r cnfs_nossum_sha1_10hashes
mkdir cnfs_nossum_sha1_10hashes
mv nossum_sha1*hashlen*.cnf ./cnfs_nossum_sha1_10hashes
mv nossum_sha1*r_0hash.cnf ./cnfs_nossum_sha1_10hashes
mv nossum_sha1*r_1hash.cnf ./cnfs_nossum_sha1_10hashes
