"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork02

    Functions:

    block_cipher_handler
"""

from impl.blockCiphers import block_cipher_cbc, block_cipher_xex, block_cipher_ctr
from util.functions import b64decode, split_blocks, bytes2int, b64encode


def block_cipher_handler(assignment, api, _log):
    """Handler-function for the 'block_cipher' type."""

    # extract config
    encrypt = assignment["operation"] == "encrypt"
    mode = assignment["opmode"]
    key = assignment["key"]

    # extract text based on operation mode
    text = b64decode(assignment["plaintext" if encrypt else "ciphertext"])
    # split text into byte blocks
    blocks = split_blocks(text)

    # match encryption/decryption mode
    # container does not run python 3.10 (match statement)? -> changed to chained if/else
    if mode == "cbc":
        # extract specific config values (iv)
        iv = b64decode(assignment["iv"])
        iv = bytes2int(iv)
        blocks = block_cipher_cbc(blocks, key, iv, api, encrypt)
    elif mode == "ctr":
        # extract specific config values (nonce)
        nonce = b64decode(assignment["nonce"])
        blocks = block_cipher_ctr(blocks, key, nonce, api)
    elif mode == "xex":
        # extract specific config values (tweak)
        tweak = b64decode(assignment["tweak"])
        blocks = block_cipher_xex(blocks, key, tweak, api, encrypt)
    else:
        raise ValueError("Unknown operation mode '" + mode + "'")

    # encode encrypted/decrypted text for submission
    return {
        "ciphertext" if encrypt else "plaintext": b64encode(b"".join(blocks))
    }
