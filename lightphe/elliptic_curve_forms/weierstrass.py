from typing import Tuple, cast
from lightphe.models.EllipticCurve import EllipticCurve

from lightphe.standard_curves.weierstrass import WeierstrassInterface
from lightphe.standard_curves import inventory


# pylint: disable=no-else-return
class Weierstrass(EllipticCurve):
    def __init__(self, curve="secp256k1"):
        """
        Create Elliptic Curve satisfying y^2 = x^3 + ax + b
        This is the most popular elliptic curve form. Bitcoin is depending on this form.
        Ref: https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/
        """
        curve_args = cast(
            WeierstrassInterface,
            inventory.build_curve(form_name="weierstrass", curve_name=curve),
        )

        # equation parameters
        self.a = curve_args.a
        self.b = curve_args.b

        # modulos
        self.modulo = curve_args.p

        # base point G
        self.G = curve_args.G

        # elliptic curve order - number of points on the curve
        self.n = curve_args.n

        # Point at infinity (sefiks.com/2023/09/29/understanding-identity-element-in-elliptic-curves)
        self.O = (float("inf"), float("inf"))

    def add_points(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """
        Find the 3rd point from given 2 points on an elliptic curve
        Args:
            P (Tuple[int, int]): 1st point on the elliptic curve
            Q (Tuple[int, int]): 2nd point on the elliptic curve
        Returns:
            P+Q (Tuple[int, int]): 3rd point on the elliptic curve
        """
        # assert self.is_on_curve(P) is True, f"{P} is not on the curve"
        # assert self.is_on_curve(Q) is True, f"{Q} is not on the curve"

        x1, y1 = P
        x2, y2 = Q

        if P == self.O:
            return Q
        elif Q == self.O:
            return P
        elif P == self.negative_point(Q):
            return self.O
        elif P == Q:
            return self.double_point(P)

        # β = (y2 - y1) / (x2 - x1)
        beta = (y2 - y1) * pow(x2 - x1, -1, self.modulo)

        # x3 = β^2 - x1 - x2
        x3 = (beta * beta - x1 - x2) % self.modulo

        # y3 = β * (x1 - x3) - y1
        y3 = (beta * (x1 - x3) - y1) % self.modulo

        assert self.is_on_curve((x3, y3)) is True

        return x3, y3

    def double_point(self, P: Tuple[int, int]) -> Tuple[int, int]:
        """
        Find a 2nd point from a given point on an elliptic curve
        Args:
            P (Tuple[int, int]): 1st point on the elliptic curve
        Returns:
            2P (Tuple[int, int]): 2nd point on the elliptic curve
        """
        # assert self.is_on_curve(P) is True, f"{P} is not on the curve"

        x1, y1 = P

        if y1 == 0:
            return self.O

        # β = (3 * x1^2 + a) / (2 * y1)
        beta = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.modulo)

        # x3 = β^2 - 2 * x1
        x3 = (beta * beta - x1 - x1) % self.modulo

        # y3 = β * (x1 - x3) - y1
        y3 = (beta * (x1 - x3) - y1) % self.modulo

        assert self.is_on_curve((x3, y3)) is True

        return x3, y3

    def negative_point(self, P: Tuple[int, int]) -> Tuple[int, int]:
        return (P[0], (-1 * P[1]) % self.modulo)

    def is_on_curve(self, P: Tuple[int, int]):
        """
        Check a given point is on an elliptic curve
        Args:
            P (Tuple[int, int]): a point with x and y coordinates
            p (int): modulo
        Returns
            is_on_curve (boolean): returns True if point is on the curve
        """
        x, y = P
        return (y * y) % self.modulo == (
            pow(x, 3, self.modulo) + self.a * x + self.b
        ) % self.modulo
