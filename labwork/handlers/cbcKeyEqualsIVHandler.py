"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork04

    Functions:

    cbc_key_equals_iv_handler
"""

from util.functions import b64decode, split_blocks, b64encode, bytes_xor


def cbc_key_equals_iv_handler(assignment, api, _log):
    """Handler-function for the 'cbc_key_equals_iv' type"""

    # extract values
    ciphertext = b64decode(assignment["valid_ciphertext"])
    keyname = assignment["keyname"]

    # split ciphertext
    blocks = split_blocks(ciphertext)
    assert len(blocks) >= 3, "Ciphertext must contain at least 3 blocks"

    # duplicate the last two blocks to keep a valid padding
    blocks.append(blocks[-2])
    blocks.append(blocks[-2])

    # set C2 (C[1]) = 0
    # so that P3 = D(C3) ^ C2 = D(C3) ^ 0 = D(C3)

    # set C3 (C[2]) = C1 (C[0])
    # so that D(C3) = C(C1)
    blocks[1] = b"\x00" * 16
    blocks[2] = blocks[0]

    # get plaintext from oracle
    plaintext = b64decode(api.query_oracle('cbc_key_equals_iv', {
        "keyname": keyname,
        "ciphertext": b64encode(b"".join(blocks))
    })['plaintext'])

    # P1 = D(C1) ^ C0
    p1 = plaintext[0:16]
    # P3 = D(C3) = D(C1)
    p3 = plaintext[32:48]

    # P1 ^ P3 = D(C1) ^ C0 ^ D(C1) = C0
    c0 = bytes_xor(p1, p3)

    return {
        "key": b64encode(c0)
    }
