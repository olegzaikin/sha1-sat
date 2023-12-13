# SHA-1:
./main --cnf --hash-function=sha1 --rounds=21 --hash-bits=160 --hash-value=0 --attack=preimage --seed=0 > sha1_preimage_21r_0hash.cnf
./main --cnf --hash-function=sha1 --rounds=21 --hash-bits=160 --hash-value=1 --attack=preimage --seed=0 > sha1_preimage_21r_1hash.cnf
./main --cnf --hash-function=sha1 --rounds=22 --hash-bits=160 --hash-value=0 --attack=preimage --seed=0 > sha1_preimage_22r_0hash.cnf
./main --cnf --hash-function=sha1 --rounds=22 --hash-bits=160 --hash-value=1 --attack=preimage --seed=0 > sha1_preimage_22r_1hash.cnf
./main --cnf --hash-function=sha1 --rounds=23 --hash-bits=160 --hash-value=0 --attack=preimage --seed=0 > sha1_preimage_23r_0hash.cnf
./main --cnf --hash-function=sha1 --rounds=23 --hash-bits=160 --hash-value=1 --attack=preimage --seed=0 > sha1_preimage_23r_1hash.cnf

# MD5:
./main --cnf --rounds=27 --hash-bits=128 --hash-value=0 --attack=preimage --seed=0 --hash-function=md5 > md5_preimage_27r_0hash.cnf
./main --cnf --rounds=27 --hash-bits=128 --hash-value=1 --attack=preimage --seed=0 --hash-function=md5 > md5_preimage_27r_1hash.cnf
./main --cnf --rounds=28 --hash-bits=128 --hash-value=0 --attack=preimage --seed=0 --hash-function=md5 > md5_preimage_28r_0hash.cnf
./main --cnf --rounds=28 --hash-bits=128 --hash-value=1 --attack=preimage --seed=0 --hash-function=md5 > md5_preimage_28r_1hash.cnf

for i in {0..7}
do
    echo $i
    # SHA-1:
    ./main --cnf --hash-function=sha1 --rounds=21 --hash-bits=160 --attack=preimage --message-file=./random_messages/random_message_${i} > sha1_preimage_21r_randomhash${i}.cnf
    ./main --cnf --hash-function=sha1 --rounds=22 --hash-bits=160 --attack=preimage --message-file=./random_messages/random_message_${i} > sha1_preimage_22r_randomhash${i}.cnf
    ./main --cnf --hash-function=sha1 --rounds=23 --hash-bits=160 --attack=preimage --message-file=./random_messages/random_message_${i} > sha1_preimage_23r_randomhash${i}.cnf
    # MD5:
    ./main --cnf --hash-function=md5 --rounds=27 --hash-bits=128 --attack=preimage --message-file=./random_messages/random_message_${i} > md5_preimage_27r_randomhash${i}.cnf
    ./main --cnf --hash-function=md5 --rounds=28 --hash-bits=128 --attack=preimage --message-file=./random_messages/random_message_${i} > md5_preimage_28r_randomhash${i}.cnf
done
