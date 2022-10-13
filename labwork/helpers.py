"""
    This file is a helper module for response program (T3INF9004: Cryptanalyses und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Functions:

    int2bytes
    bytes2int
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
