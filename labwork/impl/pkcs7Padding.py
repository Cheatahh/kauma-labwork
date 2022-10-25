"""
    This file is a helper module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Functions:

    find_padding_match
    @concurrent oracle_decrypt_pkcs7
"""

from util.functions import bytes_xor, block_size
from util.processing import concurrent


# brute force the padding match
def find_padding_match(oracle, Q, ciphertext, index):

    # go through all possible values
    for i in range(256):

        # edit the Q vector to match the padding
        Q[index] = i

        # check if the padding is correct
        if oracle(Q, ciphertext):

            # check if byte is not the last byte
            if index != block_size - 1:
                return i

            # otherwise, check if the padding is still correct if the previous byte is inverted

            # invert byte
            Q[index - 1] = ~Q[index - 1] & 0xff

            # check if the padding is still correct
            if oracle(Q, ciphertext):

                # invert byte back
                Q[index - 1] = ~Q[index - 1] & 0xff
                return i

    # no match found, should not happen
    raise Exception(f"No match found for Q = {Q.hex()} at index {index}")


# decrypt a ciphertext block using the pkcs7 oracle
#
#          C
#          v
#       decrypt <- KEY
#          v
#         D(C) = target we are trying to find
#          v
#    Q -> xor
#          v
#          P = plaintext + padding
#
@concurrent
def oracle_decrypt_pkcs7(oracle, iv, ciphertext, log):

    # initialize vector (nulls) for xor operation
    Q = bytearray(block_size)

    # initialize decrypted block D(C) = P ^ Q
    DC = bytearray(block_size)

    # go through each byte of the block reversed
    for index in range(block_size - 1, -1, -1):

        # find the padding match
        # D(C) ^ value = (block_size - index), f.e. 0x1 for the first byte
        value = find_padding_match(oracle, Q, ciphertext, index)
        log.log(f"Found valid padding at Q = {Q.hex()}", 2)

        # solve for D(C)
        DC[index] = value ^ (block_size - index)

        # change Q[index .. block_size] to ask for the next padding, f.e. 0x2 for the first byte
        for paddingIndex in range(index, block_size):
            # Q = D(C) ^ (block_size - index + 1), f.e. Q = D(C) ^ 0x2 for the first byte
            Q[paddingIndex] = DC[paddingIndex] ^ (block_size - index + 1)

    # xor the decrypted block with the original iv
    # P = D(C) ^ IV
    return bytes_xor(DC, iv)
