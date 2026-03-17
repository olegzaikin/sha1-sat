# Script for generating inverse problems for SHA-0

script_name="gen_cnfs_sha0.sh"
version="0.0.1"

cd ./scripts/
python3 ./gen_random_hashes.py
mv hashes_256bit.txt ..
cd ..
ln -s ./scripts/gen_hash_preimage_instances.py .

# SHA-0:
for rnd in {21..25}
do
    echo "sha-0, rnd=${rnd}"
    # Generate a template CNF:
    ./main --cnf --hash-function=sha0 --rounds=${rnd} --hash-value=0 --hash-bits=0 --attack=preimage --seed=0 > nossum_sha0_preimage_${rnd}r_template.cnf
    # Generate instances by adding hashes to the template CNF:
    python3 ./gen_hash_preimage_instances.py ./nossum_sha0_preimage_${rnd}r_template.cnf hashes_256bit.txt 160 10 --hashvars=./vars_nossum_sha0-${rnd}r --random
done

rm -r cnfs_nossum_sha0_10hashes
mkdir cnfs_nossum_sha0_10hashes
mv nossum_sha0*hashlen*.cnf ./cnfs_nossum_sha0_10hashes
mv nossum_sha0*r_0hash.cnf ./cnfs_nossum_sha0_10hashes
mv nossum_sha0*r_1hash.cnf ./cnfs_nossum_sha0_10hashes
