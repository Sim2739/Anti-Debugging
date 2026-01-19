#!/bin/bash
if [[ $# -lt 2 ]]; then
	echo "Usage: ./add_nanomites_elf.sh input_elf output_elf"
	exit 2
fi

input_elf=$1
output_elf=$2

python3 linux/src/prepare_packer.py $input_elf	#add encrypted nanomites to ELF
xxd -i linux/resc/nanomites_dump linux/src/nanomites_dump.h	#transform nanomites_dump into C header file
xxd -i linux/resc/nanomites_encrypted linux/src/nanomites_encrypted.h	#transform nanomites_encrypted into C header file
gcc linux/src/packer.c -lssl -lcrypto -o $output_elf		#compile all resources into single executable so it can run everywhere
