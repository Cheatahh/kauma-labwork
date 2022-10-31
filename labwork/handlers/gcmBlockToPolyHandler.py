"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork04

    Functions:

    gcm_block_to_poly_handler
"""

from impl.galoisCounterMode import gcm_polynomials_128
from util.functions import b64decode, bytes2gcm


def gcm_block_to_poly_handler(assignment, _api, _log, _case_id):
    """Handler-function for the 'gcm_block_to_poly' type"""

    # extract block
    block = b64decode(assignment["block"])

    # convert into gcm space
    value = bytes2gcm(block)

    # get polynomials
    polynomials = gcm_polynomials_128(value)

    return {
        "coefficients": polynomials,
    }
