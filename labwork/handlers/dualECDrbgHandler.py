import base64

from util.ec import EllipticCurve
from util.functions import split_blocks, b64encode, Int2bytes, bytes2Int, b64decode, truncate
from util.prime import mod_inverse


def dual_ec_drbg_next(curve, P, Q, d, output_size, drbg_output, log):

    # Q = dP, missing value could be calculated

    dm1 = mod_inverse(d, curve.n)
    drbg_output_window = drbg_output[1:]

    for high_bits in range((1 << (33 * 8 - output_size)) - 1):

        if high_bits % 20 == 0:
            log.log(f"Trying prefix range >= {20 * (high_bits // 20)}", 2)
        high_bits <<= output_size

        # guesses
        r0_x = high_bits | drbg_output[0]
        r0 = (r0_x, curve.lift_x(r0_x))

        # reverse the scalar multiplication
        # t * Q = r0                        Q = dP
        # t * d * P = r0                    * d^-1
        # t * d * d^-1 * P = r0 * d^-1
        # t * P = r0 * d^-1
        t1_x = curve.scalar_multiply(dm1, r0)[0]

        def validate_drbg_output_chain(tn_x):

            # already starting with next t
            for drbg_output_value in drbg_output_window:

                rn_x = curve.scalar_multiply(tn_x, Q)[0]
                rn_x = truncate(rn_x, output_size)
                if rn_x != drbg_output_value:
                    return None

                # feed forward
                tn_x = curve.scalar_multiply(tn_x, P)[0]

            rn_x = curve.scalar_multiply(tn_x, Q)[0]
            rn_x = truncate(rn_x, output_size)

            return rn_x

        next_r = validate_drbg_output_chain(t1_x)
        if next_r is not None:
            return next_r

def dual_ec_drbg_handler(assignment, _api, log, _case_id):

    # curve parameters
    a = 0x3
    b = 0xc2660dc9f6f5e79fd5ccc80bdacf5361870469b61646b05efe3c96c38ff96bad
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    n = 0xffffffff00000000fffffffffffffffe8f4e0793de3b9c2e0f61060a88b13657
    curve = EllipticCurve(a, b, p, n)

    # extract values
    P = base64.b64decode(assignment["P"])
    P = (bytes2Int(P[1:33]), bytes2Int(P[33:]))

    Q = base64.b64decode(assignment["Q"])
    Q = (bytes2Int(Q[1:33]), bytes2Int(Q[33:]))

    d = bytes2Int(b64decode(assignment["backdoor_key"]))

    # sanity check
    dP = curve.scalar_multiply(d, P)
    assert dP == Q

    output_size = assignment["outbits"]
    drbg_output = [bytes2Int(it) for it in split_blocks(b64decode(assignment["dbrg_output"]), output_size // 8)]

    next_r = dual_ec_drbg_next(curve, P, Q, d, output_size, drbg_output, log)

    return {
        "next": b64encode(Int2bytes(next_r))
    }