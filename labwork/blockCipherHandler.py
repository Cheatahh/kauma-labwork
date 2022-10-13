"""
    This file is a handler module for response program (T3INF9004: Cryptanalyses und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Functions:

    block_cipher_handler
"""
import base64

from labwork.blockCiphers import block_cipher_ctr, block_cipher_xex, block_cipher_cbc, block_size


def block_cipher_handler(assignment, api):
    """Handler-function for the 'block_cipher' type."""

    # extract config
    encrypt = assignment["operation"] == "encrypt"
    mode = assignment["opmode"]
    key = assignment["key"]

    # extract text based on operation mode
    text = base64.b64decode(assignment["plaintext" if encrypt else "ciphertext"])
    # checks
    assert len(text) % block_size == 0, "Text size must be a multiple of " + block_size
    # split text into byte blocks
    blocks = [
        text[(block_size * index):(block_size * (index + 1))]
        for index in range(int(len(text) / block_size))
    ]

    # match encryption/decryption mode
    match mode:
        case "cbc":
            # extract specific config values (iv)
            iv = base64.b64decode(assignment["iv"])
            iv = int.from_bytes(iv, byteorder="little")
            blocks = block_cipher_cbc(blocks, key, iv, api, encrypt)
        case "ctr":
            # extract specific config values (nonce)
            nonce = base64.b64decode(assignment["nonce"])
            blocks = block_cipher_ctr(blocks, key, nonce, api)
        case "xex":
            # extract specific config values (tweak)
            tweak = base64.b64decode(assignment["tweak"])
            blocks = block_cipher_xex(blocks, key, tweak, api, encrypt)
        case unknown:
            raise ValueError("Unknown operation mode '" + unknown + "'")

    # encode encrypted/decrypted text for submission
    return {
        "ciphertext" if encrypt else "plaintext": base64.b64encode(b"".join(blocks)).decode("utf-8")
    }
