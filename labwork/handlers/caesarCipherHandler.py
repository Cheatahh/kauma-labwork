"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork01

    Functions:

    caesar_cipher_handler
"""

from impl.streamCiphers import caesar_cipher


def caesar_cipher_handler(assignment, _api, _log, _case_id):
    """Handler-function for the 'caesar_cipher' type"""

    shift = assignment["letter_shift"]
    if assignment["action"] == "encrypt":
        # encrypt operation, shift is positive
        return caesar_cipher(assignment["plaintext"], shift)
    else:
        # decrypt operation, shift is negative
        return caesar_cipher(assignment["ciphertext"], -shift)
