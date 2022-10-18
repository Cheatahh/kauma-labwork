"""
    This file is a handler module for response program (T3INF9004: Cryptanalyses und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork01

    Functions:

    caesar_cipher_handler
"""

# Faster alternative
"""
import string

# one function for both operation; encrypt == -decrypt
# this function performs the caesar cipher operation by mapping each character to another alphabet
def caesar_cipher(text, shift):

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
"""


# preparation for vigenere; attrib(shift): replace type int with function
# perform caesar with f(x) -> (-)shift
# perform vigenere with f(x) -> (-)round_robin_shift()
def caesar_cipher(text, shift):
    def shift_char(char):
        # char is in range a - z
        if ord('a') <= char <= ord('z'):
            # 1. reduction of ord(char) into Z26
            # 2. shifting char
            # 3. mod 26 to stay in Z26
            # 4. inflating of char into original space
            return ((char - ord('a') + shift) % (ord('z') - ord('a') + 1)) + ord('a')
        # char is in range A - Z
        elif ord('A') <= char <= ord('Z'):
            return ((char - ord('A') + shift) % (ord('Z') - ord('A') + 1)) + ord('A')
        # do not shift char
        else:
            return char

    # generate string by joining all shifted chars
    return "".join(chr(shift_char(ord(char))) for char in text)


def caesar_cipher_handler(assignment, _):
    """Handler-function for the 'caesar_cipher' type"""

    shift = assignment["letter_shift"]
    if assignment["action"] == "encrypt":
        # encrypt operation, shift is positive
        return caesar_cipher(assignment["plaintext"], shift)
    else:
        # decrypt operation, shift is negative
        return caesar_cipher(assignment["ciphertext"], -shift)
