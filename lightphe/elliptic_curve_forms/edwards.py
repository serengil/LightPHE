# built-in dependencies
from typing import Tuple
from lightphe.models.EllipticCurve import EllipticCurve
from lightphe.standard_curves import edwards as EdwardsInterface

CURVE_MAP = {
    None: EdwardsInterface.Ed25519,
    "ed25519": EdwardsInterface.Ed25519,
    "ed448": EdwardsInterface.Ed448,
    "e521": EdwardsInterface.E521,
    "curve41417": EdwardsInterface.Curve41417,
    "jubjub": EdwardsInterface.JubJub,
    "mdc201601": EdwardsInterface.MDC201601,
}


class TwistedEdwards(EllipticCurve):
    """
    Builds (twisted) edwards curves satisfying the equation
        (a*x^2 + y^2) mod p = (1 + d*x^2*y^2) mod p
    Refs:
        [1] https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/
        [2] https://sefiks.com/2018/12/26/twisted-edwards-curves/
    """

    def __init__(self, curve="ed25519"):

        if curve not in CURVE_MAP:
            raise ValueError(f"Unsupported curve - {curve}")

        curve_args = CURVE_MAP[curve]()

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
