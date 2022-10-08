"""
    This file is a handler module for response program (T3INF9004: Kryptoanalyse und Methoden-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Functions:

    caesar_cipher_handler
"""

import string


# one function for both operation; encrypt == -decrypt
# this function performs the caesar cipher operation by mapping each character to another alphabet
def perform_caesar_cipher(text, shift):

    # get the ascii lowercase alphabet
    lowercase_chars = string.ascii_lowercase

    # shift alphabet
    lowercase_chars_shifted = lowercase_chars[shift:] + lowercase_chars[:shift]

    # get the ascii uppercase alphabet
    uppercase_chars = string.ascii_uppercase

    # shift alphabet
    uppercase_chars_shifted = uppercase_chars[shift:] + uppercase_chars[:shift]

    # create translation table; alphabet unions -> shifted alphabet unions
    lookup = str.maketrans(lowercase_chars + uppercase_chars, lowercase_chars_shifted + uppercase_chars_shifted)

    # map each character using the created lookup table
    # any mismatched characters will be mapped using the identity function, noop
    return text.translate(lookup)


def caesar_cipher_handler(assignment):
    """Handler-function for the 'caesar_cipher' type"""

    shift = assignment["letter_shift"]
    if assignment["action"] == "encrypt":
        # encrypt operation, shift is positive
        return perform_caesar_cipher(assignment["plaintext"], shift)
    else:
        # decrypt operation, shift is negative
        return perform_caesar_cipher(assignment["ciphertext"], -shift)
