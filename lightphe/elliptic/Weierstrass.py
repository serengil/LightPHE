from typing import Tuple
from lightphe.models.EllipticCurve import EllipticCurve


class Weierstrass(EllipticCurve):
    def __init__(self, curve="secp256k1"):
        """
        Create Elliptic Curve satisfying y^2 = x^3 + ax + b
        """
        if curve == "secp256k1":
            self.a = 0
            self.b = 7
            # modulo
            self.p = (
                pow(2, 256)
                - pow(2, 32)
                - pow(2, 9)
                - pow(2, 8)
                - pow(2, 7)
                - pow(2, 6)
                - pow(2, 4)
                - pow(2, 0)
            )
            self.G = (
                55066263022277343669578718895168534326250603453777594175500187360389116729240,
                32670510020758816978083085130507043184471273380659243275938904335757337482424,
            )
            # elliptic curve order - number of points on the curve
            self.n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

        else:
            raise ValueError(f"unimplemented curve {curve}")

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

        # check point addition or doubling required
        if x1 == x2 and y1 == y2:
            # doubling
            beta = (3 * x1 * x2 + self.a) * pow(2 * y1, -1, p)
        else:
            # addition
            beta = (y2 - y1) * pow(x2 - x1, -1, p)

        x3 = (beta * beta - x1 - x2) % p
        y3 = (beta * (x1 - x3) - y1) % p

        self.is_on_curve((x3, y3), p)

        return x3, y3

    def apply_double_and_add_method(self, G: Tuple[int, int], k: int, p: int) -> Tuple[int, int]:
        """
        Perform scalar multiplication over elliptic curve
        Args:
            G (Tuple[int, int]): a point on an elliptic curve
            k (int): scalar value
            p (int): modulo
        Returns
            kxG (Tuple[int, int])
        """
        target_point = G

        k_binary = bin(k)[2:]

        for i in range(1, len(k_binary)):
            current_bit = k_binary[i : i + 1]

            # doubling - always
            target_point = self.add_points(target_point, target_point, p)

            if current_bit == "1":
                target_point = self.add_points(target_point, G, p)

        self.is_on_curve(target_point, p)

        return target_point

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
        assert (y * y) % p == (pow(x, 3, p) + self.a * x + self.b) % p
