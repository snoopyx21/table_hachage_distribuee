#!/bin/sh

make
cd hash
make
cd ..
./client "::1" "9000" "get" "hash/hash_file" 
