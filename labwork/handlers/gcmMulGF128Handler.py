"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork04

    Functions:

    gcm_mul_gf2_128_handler
"""

from impl.galoisCounterMode import gcm_mul_gf2_128
from util.functions import b64decode, b64encode, bytes2gcm, gcm2bytes


def gcm_mul_gf2_128_handler(assignment, _api, _log, _case_id):
    """Handler-function for the 'gcm_mul_gf2_128' type"""

    # extract values
    a = bytes2gcm(b64decode(assignment["a"]))
    b = bytes2gcm(b64decode(assignment["b"]))

    # perform multiplication
    a_times_b = gcm_mul_gf2_128(a, b)

    # gcm -> bytes
    a_times_b = gcm2bytes(a_times_b)

    return {
        "a*b": b64encode(a_times_b)
    }
