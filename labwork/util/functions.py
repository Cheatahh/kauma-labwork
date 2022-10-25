"""
    This file is a helper module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Fields:

    block_size

    Functions:

    int2bytes
    bytes2int
    b64decode
    b64encode
    split_blocks
    bytes_xor
    reverse_bits
    bytes2gcm
    gcm2bytes
"""

import base64

block_size = 16


# helper function to convert an integer to a bytes block (length 16)
def int2bytes(value):
    # fixed byteorder="little"
    return value.to_bytes(byteorder="little", length=block_size)


# helper function to convert a bytes block to an integer
def bytes2int(value):
    # fixed byteorder="little"
    return int.from_bytes(value, byteorder="little")


# shorthand for base64.b64decode(text)
def b64decode(text):
    return base64.b64decode(text)


# shorthand for base64.b64decode(text).decode("utf-8")
def b64encode(text):
    return base64.b64encode(text).decode("utf-8")


# helper function to split text into byte blocks
def split_blocks(text):
    # checks
    assert len(text) % block_size == 0, f"Text size must be a multiple of {block_size}"
    return [
        text[index:index + block_size]
        for index in range(0, len(text), block_size)
    ]


# xor two byte blocks
def bytes_xor(a, b):
    return bytes(a ^ b for a, b in zip(a, b))


# reverse bits in value
def reverse_bits(value, bits):
    result = 0
    for _ in range(bits):
        result <<= 1
        result |= value & 1
        value >>= 1
    return result


# helper function to convert a bytes block to a gcm integer
def bytes2gcm(value):
    # reverse each byte
    value = bytes(reverse_bits(byte, 8) for byte in value)
    # interpret block as little endian integer
    return bytes2int(value)


# helper function to convert a gcm integer to a bytes block
def gcm2bytes(value):
    # interpret integer as little endian block
    value = int2bytes(value)
    # reverse each byte
    return bytes(reverse_bits(byte, 8) for byte in value)
