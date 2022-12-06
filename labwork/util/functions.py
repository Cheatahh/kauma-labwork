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
    truncate
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


# helper function to convert an integer to a bytes block (length = min)
def Int2bytes(value):
    # fixed byteorder="big"
    return value.to_bytes(byteorder="big", length=(value.bit_length() + 7) // 8)


# helper function to convert a bytes block to an integer
def bytes2Int(value):
    # fixed byteorder="big"
    return int.from_bytes(value, byteorder="big")


# shorthand for base64.b64decode(text)
def b64decode(text):
    return base64.b64decode(text)


# shorthand for base64.b64decode(text).decode("utf-8")
def b64encode(text):
    return base64.b64encode(text).decode("utf-8")


# helper function to split text into byte blocks
def split_blocks(text, size=block_size):
    # checks
    assert len(text) % size == 0, f"Text size must be a multiple of {size}"
    return [
        text[index:index + size]
        for index in range(0, len(text), size)
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

# truncate x down to n bits (most significant bits are discarded)
def truncate(x, bits):
    return x & ((1 << bits) - 1)
