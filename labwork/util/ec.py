from util.prime import mod_inverse


class EllipticCurve:

    def __init__(self, a, b, p, n):
        self.a = a
        self.b = b
        self.p = p
        self.n = n

    # double_and_add
    def scalar_multiply(self, k, P):
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
        if P == (None, None):
            return Q
        if Q == (None, None):
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and y1 != y2:
            return None, None
        if x1 == x2:
            m = (3 * x1 * x1 + self.a) * mod_inverse(2 * y1, self.p)
        else:
            m = (y1 - y2) * mod_inverse(x1 - x2, self.p)
        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)
        return x3 % self.p, -y3 % self.p

    def lift_x(self, x):
        return pow(x ** 3 + self.a * x + self.b, (self.p + 1) // 4, self.p)