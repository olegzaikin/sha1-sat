sha1-sat -- SAT instance generator for SHA-1, MD5, and MD4
=========================================================

### About

Sources and benchmarks for the paper

Oleg Zaikin. Inverting Step-Reduced SHA-1 and MD5 by Parameterized SAT Solvers // In CP 2024.

The sources are an extension of the repository by Vegard Nossum:

https://github.com/vegard/sha1-sat

In this extension, two new cryptographic hash functions are maintained: MD4 and MD5. 
Also, intermediate preimage attacks between rounds i and i+1 can now be generated.

### Directories overview

/cnfs_cp - main CNFs used in the CP 2024 experiments.

/data - halfadder descriptions for the ESPRESSO minimizer.

/random_messages - random messages, used to generate some CNFs.

# Compiling

./make.sh

# Running

To generate a CNF encoding a preimage attack on 23 first rounds
(out of 80) of SHA-1, run:

> ./main --cnf --rounds=23 --hash-bits=160 > instance.cnf

To generate CNFs encoding standard (non-intermediate) preimage attacks
on 27-, 28-, and 29-round MD5 and 21-, 22-, 23-, and 24-round SHA-1, run:

> ./gen_cnfs.sh

To generate CNFs encoding intermediate preimage attacks between
28- and 29-round MD5 and between 23-, and 24-round SHA-1, run:

> ./gen_weakM_cnfs.sh

### Citation
If you use these sources or/and data, please cite:
```
@inproceedings{Zaikin-CP2024,
  author       = {Oleg Zaikin},
  title        = {Inverting Step-Reduced {SHA-1} and {MD5} by Parameterized {SAT} Solvers},
  booktitle    = {CP},
  pages        = {31:1--31:19},
  year         = {2024}
}

```
