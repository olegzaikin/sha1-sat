python3 ./gen_weakM_cbmc.py ./cbmc_md5-28_1hash_bitM_base.c
python3 ./gen_weakM_cbmc.py ./cbmc_md5-29_1hash_bitM_base.c

for f in ./cbmc_*.c
do
 echo "Processing $f"
 base_name=$(basename -- "$f" .c)
 #echo $base_cnfname
 cbmc $f --dimacs --outfile ${base_name}.cnf &> log_cbmc_${base_name} &
done
