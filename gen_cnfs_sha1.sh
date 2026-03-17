# Script for generating inverse problems for SHA-1

script_name="gen_cnfs_sha1.sh"
version="0.0.1"

cd ./scripts/
python3 ./gen_random_hashes.py
mv hashes_256bit.txt ..
cd ..
ln -s ../EnCnC/scripts/gen_hash_preimage_instances.py .

# SHA-1:
for rnd in {21..25}
do
    echo "sha-1, rnd=${rnd}"
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
