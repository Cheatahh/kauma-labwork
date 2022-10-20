"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork03

    Functions:

    pkcs7_padding_handler
"""
import base64

from util.api import verbosity
from util.converters import split_blocks
from util.pkcs7padding import decrypt_pkcs7_oracle


def pkcs7_padding_handler(_id, assignment, api, progress):
    """Handler-function for the 'pkcs7_padding' type"""

    # extract from assignment
    ciphertext = base64.b64decode(assignment["ciphertext"])
    iv = base64.b64decode(assignment["iv"])

    # split ciphertext into 128bit blocks
    blocks = split_blocks(ciphertext)

    # go through each block reversed (cbc decrypt)
    for index in range(len(blocks) - 1, -1, -1):

        # log
        progress.update("[#%d] Processing block #%d\n" % (_id, index), 2)

        # current vector is previous ciphertext block, or iv if first block
        cv = blocks[index - 1] if index != 0 else iv

        # decrypt the block
        P = decrypt_pkcs7_oracle(assignment["keyname"], cv, blocks[index], _id, api, progress)

        blocks[index] = P

    # join all blocks together
    blocks = b"".join([*blocks])

    # extract padding
    padding = blocks[-1]

    # remove padding from block
    blocks = blocks[:-padding]

    # pack plaintext
    blocks = base64.b64encode(blocks).decode("utf-8")

    return {
        "plaintext": blocks
    }
