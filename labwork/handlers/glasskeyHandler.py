"""
    This file is a handler module for response program (T3INF9004: Cryptanalysis und Method-Audit).

    License: CC-0
    Authors: DHBW Students 200374 & 200357 (2022)
    Component: Labwork09

    Functions:

    glasskey_handler
"""

import hashlib
import random
from hmac import HMAC

from util.functions import b64decode, bytes2Int, b64encode, Int2bytes


def hmac_sha256(key, data):
    return HMAC(key, data, hashlib.sha256).digest()


def gk_drbg(drbg_key, index):
    data = index.to_bytes(4, "big")
    mic = hmac_sha256(drbg_key, data)
    return mic[0]


def round_up(value, multiple):
    return (value + multiple - 1) // multiple


def gen_bitmask(bit_len):
    assert(bit_len > 0)
    return (1 << bit_len) - 1


def set_bit(self, bit):
    self |= (1 << bit)
    return self


def gk_intrg(drbg_key, bit_len):
    if (bit_len % 8) != 0:
        byte_count = round_up(bit_len, 8)
    else:
        byte_count = bit_len // 8
    values = []
    for i in range(byte_count):
        values.append(gk_drbg(drbg_key, i))
    raw_integer = bytes2Int(values)
    bit_mask = gen_bitmask(bit_len)
    raw_integer &= bit_mask
    raw_integer = set_bit(raw_integer, bit_len - 1)
    return raw_integer


def gk_candprime(drbg_key, bit_len):
    raw_integer = gk_intrg(drbg_key, bit_len)
    raw_integer = set_bit(raw_integer, 0)
    raw_integer = set_bit(raw_integer, bit_len - 2)
    return raw_integer


def is_prime_miller_rabin(n, k=400):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gk_nextprime(value):
    value = set_bit(value, 0)
    while True:
        if is_prime_miller_rabin(value):
            return value
        value += 2


def gk_primerg(drbg_key, bit_len):
    candidate = gk_candprime(drbg_key, bit_len)
    return gk_nextprime(candidate)


def gk_pgen(drbg_key, modulus_bit_len):
    p_bit_len = modulus_bit_len // 2
    return gk_primerg(drbg_key, p_bit_len)


def gk_derive_drbg_key(agency_key, seed):
    assert(isinstance(seed, bytes))
    assert(len(seed) == 8)
    return hashlib.sha256(agency_key + seed).digest()


def gk_p_from_seed(agency_key, seed, modulus_bit_len):
    drbg_key = gk_derive_drbg_key(agency_key, seed)
    p = gk_pgen(drbg_key, modulus_bit_len)
    return p


def extract_topmost_bits(value, bit_len):
    assert(bit_len > 0)
    assert(bit_len <= value.bit_length())
    mask = gen_bitmask(bit_len)
    mask = mask << (value.bit_length() - bit_len)
    return (value & mask) >> (value.bit_length() - bit_len)


def gk_rsa_escrow(agency_key, n):
    seed = extract_topmost_bits(n, 64).to_bytes(8, "big")
    modulus_bit_len = n.bit_length()
    p = gk_p_from_seed(agency_key, seed, modulus_bit_len)
    assert (n % p) == 0
    q = n // p
    return p, q


def glasskey_handler(assignment, _api, _log, _case_id):
    """Handler-function for the 'glasskey' type"""

    # extract values
    agency_key = b64decode(assignment["agency_key"])
    e = assignment["e"]
    n = bytes2Int(b64decode(assignment["n"]))

    p, q = gk_rsa_escrow(agency_key, n)

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)  # e * d = 1 mod phi, modular inverse

    return {
        "d": b64encode(Int2bytes(d))
    }
