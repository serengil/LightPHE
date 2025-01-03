from typing import Tuple
from lightphe.models.EllipticCurve import EllipticCurve
from lightphe.standard_curves import weierstrass as WeierstrassInterface

CURVE_MAP = {
    None: WeierstrassInterface.Secp256k1,
    "secp256k1": WeierstrassInterface.Secp256k1,
    "p192": WeierstrassInterface.P192,
    "secp192r1": WeierstrassInterface.P192,
    "prime192v1": WeierstrassInterface.P192,
    "p224": WeierstrassInterface.P224,
    "secp224r1": WeierstrassInterface.P224,
    "wap-wsg-idm-ecid-wtls12": WeierstrassInterface.P224,
    "ansip224r1": WeierstrassInterface.P224,
    "p256": WeierstrassInterface.P256,
    "secp256r1": WeierstrassInterface.P256,
    "prime256v1": WeierstrassInterface.P256,
    "p384": WeierstrassInterface.P384,
    "secp384r1": WeierstrassInterface.P384,
    "ansip384r1": WeierstrassInterface.P384,
    "p521": WeierstrassInterface.P521,
    "secp521r1": WeierstrassInterface.P521,
    "ansip521r1": WeierstrassInterface.P521,
    "curve22103": WeierstrassInterface.Curve22103,
    "curve4417": WeierstrassInterface.Curve4417,
    "curve1174": WeierstrassInterface.Curve1174,
    "curve67254": WeierstrassInterface.Curve67254,
    "fp254bna": WeierstrassInterface.Fp254BNa,
    "fp254bnb": WeierstrassInterface.Fp254BNb,
    "fp224bn": WeierstrassInterface.Fp224BN,
    "fp256bn": WeierstrassInterface.Fp256BN,
    "fp384bn": WeierstrassInterface.Fp384BN,
    "fp512bn": WeierstrassInterface.Fp512BN,
    "tweedledum": WeierstrassInterface.Tweedledum,
    "tweedledee": WeierstrassInterface.Tweedledee,
    "pallas": WeierstrassInterface.Pallas,
    "vesta": WeierstrassInterface.Vesta,
    "tom256": WeierstrassInterface.Tom256,
}


class Weierstrass(EllipticCurve):
    def __init__(self, curve="secp256k1"):
        """
        Create Elliptic Curve satisfying y^2 = x^3 + ax + b
        This is the most popular elliptic curve form. Bitcoin is depending on this form.
        Ref: https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/
        """

        if curve not in CURVE_MAP:
            raise ValueError(f"Unsupported curve - {curve}")

        curve_args = CURVE_MAP[curve]()

        # equation parameters
        self.a = curve_args.a
        self.b = curve_args.b

        # modulos
        self.p = curve_args.p

        # base point G
        self.G = curve_args.G
        # elliptic curve order - number of points on the curve
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

        # check point addition or doubling required
        if x1 == x2 and y1 == y2:
            # doubling
            beta = (3 * x1 * x2 + self.a) * pow(2 * y1, -1, p)
        else:
            # addition
            beta = (y2 - y1) * pow(x2 - x1, -1, p)

        x3 = (beta * beta - x1 - x2) % p
        y3 = (beta * (x1 - x3) - y1) % p

        assert self.is_on_curve((x3, y3), p) is True

        return x3, y3

    def negative_point(self, P: Tuple[int, int], p: int) -> Tuple[int, int]:
        return (P[0], (-1 * P[1]) % p)

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
        return (y * y) % p == (pow(x, 3, p) + self.a * x + self.b) % p
