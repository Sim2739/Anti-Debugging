import random
import hashlib
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
import os


def derive_key_nonce(seed):
    md1 = hashlib.md5(seed.to_bytes(4, "little")).digest()
    md2 = hashlib.md5(seed.to_bytes(5, "little")).digest()
    md3 = hashlib.md5(seed.to_bytes(6, "little")).digest()

    key = md1 + md2         # 32 bytes
    nonce = md3[:12]        # 12 bytes
    nonce = nonce + b"\x00" * 4 

    return key, nonce


def encrypt_code(data, encrypted_start):
    seed = 0x12345678   # any constant value
    key, nonce = derive_key_nonce(seed)


    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()

    block = data[encrypted_start : encrypted_start + 8]
    encrypted_block = encryptor.update(block)

    for i in range(8):
        data[encrypted_start + i] = encrypted_block[i]

    return (encrypted_start, seed)


def implement_nanomites(data, index, end_index):
    nanomites = []

    available_space = end_index - index - 10
    code_steals = available_space // 16

    data[index] = 0xcc
    data[end_index] = 0xcc

    encrypted_start = index + 10
    for i in range(code_steals):
        nanomites.append(encrypt_code(data, encrypted_start))
        encrypted_start += 16

    return nanomites


def dump_nanomites(nanomites, filename):
    with open(filename, "w") as f:
        f.write(str(len(nanomites)) + "\n")
        for offset, seed in nanomites:
            f.write(f"{offset}:{seed}\n")


def add_nanomites(input_filename, output_filename):
    
    with open(input_filename, "rb") as f:
        data = bytearray(f.read())

    nanomites = []
    for i in range(len(data)):
        if data[i:i+6] == b"\x49\xbf\x55\xb0\xfe\xca":
            index = i
            end_index = index + data[i:].find(b"\x49\xbf\x55\x10\xfe\xca")
            nanomites.extend(implement_nanomites(data, index, end_index))

    dump_nanomites(nanomites, "linux/resc/nanomites_dump")

    with open(output_filename, "wb") as f:
        f.write(data)


if len(sys.argv) < 2:
    print("Provide ELF filename.")
else:
    add_nanomites(sys.argv[1], "linux/resc/nanomites_encrypted")
