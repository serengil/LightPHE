from typing import Tuple
from lightphe.models.EllipticCurve import EllipticCurve


class TwistedEdwards(EllipticCurve):
    """
    Builds (twisted) edwards curves
    Refs:
        [1] https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/
        [2] https://sefiks.com/2018/12/26/twisted-edwards-curves/
    """
    def __init__(self, curve="ed25519"):

        if curve != "ed25519":
            raise ValueError(f"unimplemented curve - {curve}")

        # (a*x^2 + y^2) mod p = (1 + d*x^2*y^2) mod p
        self.p = pow(2, 255) - 19
        self.a = -1
        self.d = (-121665 * pow(121666, -1, self.p)) % self.p

        # base point G
        u = 9
        g_y = ((u - 1) * pow(u + 1, -1, self.p)) % self.p
        g_x = 15112221349535400772501151409588531511454012693041857206046113283949847762202
        self.G = (g_x, g_y)

        # elliptic curve order - number of points on the curve
        self.n = pow(2, 253) + 27742317777372353535851937790883648493

    def add_points(self, P: Tuple[int, int], Q: Tuple[int, int], p: int) -> Tuple[int, int]:
        """
        Find the 3rd point from given 2 points on an elliptic curve
        Args:
            P (Tuple[int, int]): 1st point on the elliptic curve
            Q (Tuple[int, int]): 2nd point on the elliptic curve
        Returns:
            P+Q (Tuple[int, int]): 3rd point on the elliptic curve
        """
        x1, y1 = P
        x2, y2 = Q

        x3 = (((x1 * y2 + y1 * x2) % p) * pow(1 + self.d * x1 * x2 * y1 * y2, -1, p)) % p
        y3 = (((y1 * y2 - self.a * x1 * x2) % p) * pow(1 - self.d * x1 * x2 * y1 * y2, -1, p)) % p

        return (x3, y3)

    def negative_point(self, P: Tuple[int, int], p: int) -> Tuple[int, int]:
        return (-P[0], P[1])

    def is_on_curve(self, P: Tuple[int, int], p: int):
        """
        Check a given point is on an elliptic curve
        Args:
            P (Tuple[int, int]): a point with x and y coordinates
            p (int): modulo
        Returns
            is_on_curve (boolean): returns True if point is on the curve
        """
        x, y = P
        return (self.a * x * x + y * y) % p == (1 + self.d * x * x * y * y) % p
