"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork02

    Functions:

    mul_gf_128_handler
"""
import base64


from util.converters import bytes2int, int2bytes


# multiply value by alpha
def mul_gf_128(value):

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


def mul_gf_128_handler(_0, assignment, _1, _2):
    """Handler-function for the 'mul_gf_128' type"""

    # decode base64 string to raw bytes
    block = base64.b64decode(assignment["block"])

    # decode bytes to little endian int
    block = bytes2int(block)

    # multiply by alpha (x)
    block = mul_gf_128(block)

    # encode int to bytes (length 16 bytes = 128 bits)
    block = int2bytes(block)

    # encode bytes to base64 string
    block = base64.b64encode(block).decode("utf-8")

    return {
        "block_times_alpha": block
    }
