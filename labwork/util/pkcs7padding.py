"""
    This file is a helper module for response program (T3INF9004: Cryptanalyses und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Functions:

    find_padding_match
    decrypt_pkcs7_oracle
"""
import base64

from util.converters import block_size, bytes_xor


# helper function to perform oracle queries
def oracle_pkcs7_padding(api, keyname, iv, ciphertext):
    return api.query_oracle("pkcs7_padding", {
        "keyname": keyname,
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    })["status"] == "padding_correct"


# brute force the padding match
def find_padding_match(keyname, cv, ciphertext, byte_index, api):

    # go through all possible values
    for i in range(256):

        # edit the cv to match the padding
        cv[byte_index] = i

        # check if the padding is correct
        if oracle_pkcs7_padding(api, keyname, cv, ciphertext):

            # check if byte is the last byte
            if byte_index == block_size - 1:

                # invert byte
                cv[byte_index - 1] = ~cv[byte_index - 1] & 0xff

                # check if the padding is still correct
                if oracle_pkcs7_padding(api, keyname, cv, ciphertext):

                    # invert byte back
                    cv[byte_index - 1] = ~cv[byte_index - 1] & 0xff
                    return i
            else:
                return i

    # no match found, should not happen
    return None


# decrypt a ciphertext block using the pkcs7 oracle
def decrypt_pkcs7_oracle(keyname, iv, ciphertext, api):

    # initialize vector (nulls) for xor operation
    Q = bytearray(block_size)

    # initialize decrypted block D(C) = P ^ Q
    DC = bytearray(block_size)

    # go through each byte of the block reversed
    for index in range(block_size - 1, -1, -1):

        # find the padding match
        # D(C) ^ value = (block_size - index), f.e. 0x1 for the first byte
        value = find_padding_match(keyname, Q, ciphertext, index, api)

        # solve for D(C)
        DC[index] = value ^ (block_size - index)

        # change Q[index .. block_size] to ask for the next padding, f.e. 0x2 for the first byte
        for paddingIndex in range(index, block_size):
            # Q = D(C) ^ (block_size - index + 1), f.e. Q = D(C) ^ 0x2 for the first byte
            Q[paddingIndex] = DC[paddingIndex] ^ (block_size - index + 1)

    # xor the decrypted block with the original iv
    # P = D(C) ^ IV
    return bytes_xor(DC, iv)
