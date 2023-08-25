#!/bin/sh

make
cd hash
make
cd ..
./client "::1" "9000" "put" "hash/hash_file" "::1"
