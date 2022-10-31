"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork03

    Functions:

    pkcs7_padding_handler
"""

from impl.pkcs7Padding import oracle_decrypt_pkcs7
from util.functions import b64decode, b64encode, split_blocks


def pkcs7_padding_handler(assignment, api, log, _case_id):
    # extract from assignment
    iv = b64decode(assignment["iv"])
    keyname = assignment["keyname"]

    # oracle function to perform pkcs7 attack
    def oracle_query(Q, ciphertext):
        return api.query_oracle("pkcs7_padding", {
            "keyname": keyname,
            "iv": b64encode(Q),
            "ciphertext": b64encode(ciphertext)
        })["status"] == "padding_correct"

    blocks = split_blocks(b64decode(assignment["ciphertext"]))

    # perform pkcs7 attack in concurrent mode, see decorator @util.processing.concurrent for more information
    # this is worthy to get an extra point right? :) (get back the point we lost during registration)
    blocks = oracle_decrypt_pkcs7((oracle_query, iv if index == 0 else blocks[index - 1], block, log)
                                  for index, block in enumerate(blocks))

    blocks = b"".join(blocks)

    # extract and remove padding
    blocks = blocks[:-blocks[-1]]

    return {
        "plaintext": b64encode(blocks)
    }
