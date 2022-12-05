import base64

from util.functions import split_blocks, b64encode, Int2bytes


def truncate(x, bits):
    return x & ((1 << bits) - 1)

class EllipticCurve:

    def __init__(self, a, b, p, n):
        self.a = a
        self.b = b
        self.p = p
        self.n = n

    def __repr__(self):
        return "y^2 = x^3 + %dx + %d" % (self.a, self.b)

    def contains(self, x, y):
        return y**2 == x**3 + self.a*x + self.b

    def __contains__(self, point):
        return self.contains(*point)

    def scalar_mult(self, k, P):
        """Scalar multiplication of a point P by a scalar k"""
        assert k >= 0
        if k == 0 or P == (None, None):
            return None, None
        Q = P
        R = (None, None)
        while k:
            if k & 1:
                R = self.add_points(R, Q)
            Q = self.add_points(Q, Q)
            k >>= 1
        return R

    def add_points(self, P, Q):
        """Add two points P and Q on the elliptic curve defined by a, b"""
        if P == (None, None):
            return Q
        if Q == (None, None):
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and y1 != y2:
            return None, None
        if x1 == x2:
            m = (3 * x1 * x1 + self.a) * self.inverse_mod(2 * y1, self.p)
        else:
            m = (y1 - y2) * self.inverse_mod(x1 - x2, self.p)
        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)
        return x3 % self.p, -y3 % self.p

    def inverse_mod(self, k, p):
        """Returns the inverse of k modulo p.
        This function returns the only integer x such that (x * k) % p == 1.
        k must be non-zero and p must be a prime.
        """
        if k == 0:
            raise ZeroDivisionError('division by zero')
        if k < 0:
            # k ** -1 = p - (-k) ** -1  (mod p)
            return p - self.inverse_mod(-k, p)
        # Extended Euclidean algorithm.
        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = p, k
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t
        gcd, x, y = old_r, old_s, old_t
        assert gcd == 1
        assert (k * x) % p == 1
        return x % p

    def order(self):
        """Returns the order of the curve"""
        return self.p + 1 - self.a - self.b

    def lift_x(self, x):
        """Returns the y coordinate of the point with x coordinate x"""
        return pow(x**3 + self.a * x + self.b, (self.p + 1) // 4, self.p)

    def get_next(self, P, Q, d, bits, drbg_output, log):
        dm1 = self.inverse_mod(d, n)
        for high_bits in range(2 ** 16):
            log.log(high_bits, 0)
            high_bits <<= 248
            r0Guess = high_bits | drbg_output[0]
            guess = (r0Guess, self.lift_x(r0Guess))
            t = self.scalar_mult(dm1, guess)[0]
            r = truncate(self.scalar_mult(t, Q)[0], bits)

            def check(r, t):
                if r == drbg_output[1]:
                    log.log("Found!", 0)
                    for drbg_output_value in drbg_output[2:]:
                        t = self.scalar_mult(t, P)[0]
                        r = truncate(self.scalar_mult(t, Q)[0], bits)
                        if r != drbg_output_value:
                            return None
                    t = self.scalar_mult(t, P)[0]
                    r = truncate(self.scalar_mult(t, Q)[0], bits)
                    return r

            r = check(r, t)
            if r is not None:
                return r

a = 0x3
b = 0xc2660dc9f6f5e79fd5ccc80bdacf5361870469b61646b05efe3c96c38ff96bad
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
n = 0xffffffff00000000fffffffffffffffe8f4e0793de3b9c2e0f61060a88b13657

c = EllipticCurve(a, b, p, n)

def dual_ec_drbg_handler(assignment, _api, log, _case_id):

    P = base64.b64decode(assignment["P"])
    P_x = int.from_bytes(P[1:33], "big")
    P_y = int.from_bytes(P[33:], "big")
    P = (P_x, P_y)

    Q = base64.b64decode(assignment["Q"])
    Q_x = int.from_bytes(Q[1:33], "big")
    Q_y = int.from_bytes(Q[33:], "big")
    Q = (Q_x, Q_y)

    d = int.from_bytes(base64.b64decode(assignment["backdoor_key"]), "big")

    dP = c.scalar_mult(d, P)
    assert dP == Q

    #print("P =", P)
    #print("d =", d)
    #print("dP =", dP)
    #print("Q =", Q)

    drbg_output = [int.from_bytes(it, "big") for it in split_blocks(base64.b64decode(assignment["dbrg_output"]), 31)]

    res = c.get_next(P, Q, d, assignment["outbits"], drbg_output, log)

    return {
        "next": b64encode(Int2bytes(res))
    }


# Q = d * P
# dm1 * Q = dm1 * d * P
# dm1 * Q = P

# P_ex = c.scalar_mult(dm1, Q)
# print("P_ex =", P_ex)