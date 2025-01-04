from typing import Tuple
from lightphe.models.EllipticCurve import EllipticCurve
from lightphe.standard_curves import weierstrass as WeierstrassInterface
from lightphe.standard_curves import inventory


class Weierstrass(EllipticCurve):
    def __init__(self, curve="secp256k1"):
        """
        Create Elliptic Curve satisfying y^2 = x^3 + ax + b
        This is the most popular elliptic curve form. Bitcoin is depending on this form.
        Ref: https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/
        """
        curve_args: WeierstrassInterface = inventory.build_curve(
            form_name="weierstrass", curve_name=curve
        )

        # equation parameters
        self.a = curve_args.a
        self.b = curve_args.b

        # modulos
        self.p = curve_args.p

        # base point G
        self.G = curve_args.G
        # elliptic curve order - number of points on the curve
        self.n = curve_args.n

    def add_points(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
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

        # check point addition or doubling required
        if x1 == x2 and y1 == y2:
            # doubling
            beta = (3 * x1 * x2 + self.a) * pow(2 * y1, -1, self.p)
        else:
            # addition
            beta = (y2 - y1) * pow(x2 - x1, -1, self.p)

        x3 = (beta * beta - x1 - x2) % self.p
        y3 = (beta * (x1 - x3) - y1) % self.p

        assert self.is_on_curve((x3, y3)) is True

        return x3, y3

    def negative_point(self, P: Tuple[int, int]) -> Tuple[int, int]:
        return (P[0], (-1 * P[1]) % self.p)

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
        return (y * y) % self.p == (pow(x, 3, self.p) + self.a * x + self.b) % self.p
