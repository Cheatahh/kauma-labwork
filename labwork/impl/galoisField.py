"""
    This file is a helper module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)

    Functions:

    mul_gf_128
"""


# multiply value by alpha
def mul_gf2_128(value):

    # multiply each polynomial component by alpha (x)
    # f.e: (x^3 + 1) * x = x^4 + x -> binary left shift
    value <<= 1

    # test if the shift resulted in an overflow of the F128 space
    # -> test if bit 129 (index 128) is set, alternative to value.bit_length() > 128
    if value & (0b1 << 128):

        # perform modular reduce
        # reduce by x^128 = x^7 + x^2 + x + 1 -> x^128 + x^7 + x^2 + x + 1

        # xor with x^7 + x^2 + x + 1
        value ^= 0b10000111

        # xor of x^128 by setting bit 129 (index 128) to 0
        # should be ~(0b1 << 128), does result in a negative value?
        value &= (0b1 << 128) - 1

    return value


def mul_gf2_8(value):
    value <<= 1
    if value & (0b1 << 8):
        value ^= 0b01001101
        value &= (0b1 << 8) - 1
    return value
