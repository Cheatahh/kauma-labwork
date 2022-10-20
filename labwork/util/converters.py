"""
    This file is a helper module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Functions:

    int2bytes
    bytes2int
    split_blocks
    xor
"""

block_size = 16


# helper function to convert an integer to a bytes block (length 16)
def int2bytes(value):
    # fixed byteorder="little", as python (usually) uses the system-default endian
    return value.to_bytes(byteorder="little", length=block_size)


# helper function to convert a bytes block to an integer
def bytes2int(value):
    # fixed byteorder="little", as python (usually) uses the system-default endian
    return int.from_bytes(value, byteorder="little")


# helper function to split text into byte blocks
def split_blocks(text):
    # checks
    assert len(text) % block_size == 0, "Text size must be a multiple of " + str(block_size)
    return [
        text[(block_size * index):(block_size * (index + 1))]
        for index in range(int(len(text) / block_size))
    ]


# xor two byte blocks
def bytes_xor(a, b):
    return bytes(a[i] ^ b[i] for i in range(len(a)))
