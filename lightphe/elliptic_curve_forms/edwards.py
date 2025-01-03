from typing import Tuple
from lightphe.models.EllipticCurve import EllipticCurve
from lightphe.elliptic_curves.edwards import TwistedEdwards as TwistedEdwardsInterface


# pylint: disable=too-few-public-methods
class Ed25519(TwistedEdwardsInterface):
    p = pow(2, 255) - 19
    a = -1
    d = (-121665 * pow(121666, -1, p)) % p

    u = 9
    g_y = ((u - 1) * pow(u + 1, -1, p)) % p
    g_x = 15112221349535400772501151409588531511454012693041857206046113283949847762202
    G = (g_x, g_y)

    n = pow(2, 253) + 27742317777372353535851937790883648493


class Ed448(TwistedEdwardsInterface):
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    a = 1
    d = 0xD78B4BDC7F0DAF19F24F38C29373A2CCAD46157242A50F37809B1DA3412A12E79CCC9C81264CFE9AD080997058FB61C4243CC32DBAA156B9
    G = (
        0x79A70B2B70400553AE7C9DF416C792C61128751AC92969240C25A07D728BDC93E21F7787ED6972249DE732F38496CD11698713093E9C04FC,
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80000000000000000000000000000000000000000000000000000001,
    )
    n = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3


class TwistedEdwards(EllipticCurve):
    """
    Builds (twisted) edwards curves satisfying the equation
        (a*x^2 + y^2) mod p = (1 + d*x^2*y^2) mod p
    Refs:
        [1] https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/
        [2] https://sefiks.com/2018/12/26/twisted-edwards-curves/
    """

    def __init__(self, curve="ed25519"):

        if curve is None or curve == "ed25519":
            curve_args = Ed25519()
        elif curve == "ed448":
            curve_args = Ed448()
        else:
            raise ValueError(f"unimplemented curve - {curve}")

        # modulo
        self.p = curve_args.p

        # equation parameters
        self.a = curve_args.a
        self.d = curve_args.d

        # base point G
        self.G = curve_args.G

        # elliptic curve order (number of points on the curve)
        self.n = curve_args.n

    def add_points(
        self, P: Tuple[int, int], Q: Tuple[int, int], p: int
    ) -> Tuple[int, int]:
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

        x3 = (
            ((x1 * y2 + y1 * x2) % p) * pow(1 + self.d * x1 * x2 * y1 * y2, -1, p)
        ) % p
        y3 = (
            ((y1 * y2 - self.a * x1 * x2) % p)
            * pow(1 - self.d * x1 * x2 * y1 * y2, -1, p)
        ) % p

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
