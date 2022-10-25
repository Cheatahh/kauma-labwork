"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork02

    Functions:

    mul_gf_128_handler
"""

from impl.galoisField import mul_gf2_128
from util.functions import b64decode, bytes2int, int2bytes, b64encode


def mul_gf_128_handler(assignment, _api, _log):
    """Handler-function for the 'mul_gf_128' type"""

    # decode base64 string to raw bytes
    block = b64decode(assignment["block"])

    # decode bytes to little endian int
    block = bytes2int(block)

    # multiply by alpha (x)
    block = mul_gf2_128(block)

    # encode int to bytes
    block = int2bytes(block)

    # encode bytes to base64 string
    block = b64encode(block)

    return {
        "block_times_alpha": block
    }
