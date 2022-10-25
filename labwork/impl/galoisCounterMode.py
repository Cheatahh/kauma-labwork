from impl.galoisField import mul_gf2_128


def gcm_polynomials_128(value):

    # value gcm integer
    # go through each bit 128..0 starting from the left
    # if bit[idx] is set -> add the corresponding polynomial
    polynomials = [idx for idx in range(127, -1, -1) if 1 << idx & value]

    # polynomials are in descending order
    # just to be sure, reverse() should also to the trick
    polynomials.sort()

    return polynomials


def gcm_mul_gf2_128(value_a, value_b):

    # get polynomials
    polynomials = gcm_polynomials_128(value_b)

    result = 0
    for idx in range(128):

        # checks if polynomial is set -> add to result (xor)
        # this could also be done using a bit mask with b,
        # I just felt like using the previous function is more pretty
        if idx in polynomials:
            result ^= value_a

        # multiply a by x (alpha)
        value_a = mul_gf2_128(value_a)

    return result
