for i in {0..7}
do
    echo $i
    ./main --cnf --rounds=22 --hash-bits=160 --attack=preimage --message-file=random_message_${i} > sha1_preimage_22r_randomhash${i}.cnf
    ./main --cnf --rounds=23 --hash-bits=160 --attack=preimage --message-file=random_message_${i} > sha1_preimage_23r_randomhash${i}.cnf
done
