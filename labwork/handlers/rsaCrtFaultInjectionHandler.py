"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork08

    Functions:

    rsa_crt_fault_injection_handler
"""

import hashlib
from math import gcd

from util.functions import b64decode, b64encode, bytes2Int, Int2bytes


# create input for signing function
# resulting bytestring = 0x( 01 ff * x 00 [MSG_MD5] )
#                          [  length = modulo_len   ]
def m_from_msg(msg, modulo_len):
    md5 = hashlib.md5(msg).digest()
    padding = b"\x01" + b"\xff" * (modulo_len - len(md5) - 2) + b"\x00"
    return padding, bytes2Int(padding + md5)


# recover p using list of signatures, public key and padded message
def recover_p(sigs, e, n, m, padding):
    for sig in sigs:
        se = pow(sig, e, n)

        # at this point we need to check, whether the signature is actually the corrupted one
        # this can be done in two ways:
        # 1. check whether the first bytes of the signature are the same as the padding (prefix)
        # 2. use the calculated p to satisfy the equation: s^e = m mod p

        # 1. version, can discard directly, requires padding
        corrupted = Int2bytes(se)[:len(padding)] != padding
        if corrupted:
            p_candidate = gcd((se - m), n)
            return p_candidate

        # 2. version, requires full calculation of p
        p_candidate = gcd(se - m, n)
        if pow(sig, e, p_candidate) != m:
            return p_candidate

    raise ValueError("No corrupted signature found")


# full private key recovery using list of signatures, public key and padded message
def recover_private_keys(sigs, e, n, m, padding):
    p = recover_p(sigs, e, n, m, padding)
    q = n // p  # p * q = n
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)  # e * d = 1 mod phi, modular inverse
    return p, q, d


def rsa_crt_fault_injection_handler(assignment, _api, _log, _case_id):
    """Handler-function for the 'rsa_crt_fault_injection' type"""

    # extract values
    msg = b64decode(assignment["msg"])
    e = bytes2Int(b64decode(assignment["pubkey"]["e"]))
    n = b64decode(assignment["pubkey"]["n"])
    sigs = [bytes2Int(b64decode(sig)) for sig in assignment["sigs"]]

    padding, m = m_from_msg(msg, len(n))
    n = bytes2Int(n)

    p, q, d = recover_private_keys(sigs, e, n, m, padding)

    # p is always smaller than q, swap if necessary
    if p > q:
        p, q = q, p

    return {
        "p": b64encode(Int2bytes(p)),
        "q": b64encode(Int2bytes(q)),
        "d": b64encode(Int2bytes(d))
    }
