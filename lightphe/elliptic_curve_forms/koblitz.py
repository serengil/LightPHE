# built-in dependencies
from typing import Tuple, Optional, cast

# project dependencies
from lightphe.models.EllipticCurve import EllipticCurve
from lightphe.commons import binary_operations as bin_ops
from lightphe.standard_curves import inventory
from lightphe.models.Curve import KoblitzInterface


# pylint: disable=no-else-return, too-many-instance-attributes
class Koblitz(EllipticCurve):
    def __init__(self, curve: Optional[str] = "k163"):
        """
        Create Elliptic Curve satisfying y^2 + xy = x^3 + ax ^2+ b
        References:
            [1] sefiks.com/2016/03/13/the-math-behind-elliptic-curves-over-binary-field/
            [2] Susantio, D. R., & Muchtadi-Alamsyah, I. (2016, April).
                Implementation of elliptic curve cryptography in binary field.
                In Journal of Physics: Conference Series (Vol. 710, No. 1, p. 012022).
                Available at: iopscience.iop.org/article/10.1088/1742-6596/710/1/012022/pdf
        """
        curve_args = cast(
            KoblitzInterface,
            inventory.build_curve(form_name="koblitz", curve_name=curve),
        )

        # Point at infinity
        self.O = ("0", "0")

        # degree of the irreducible polynomial
        self.m = curve_args.m

        # coefficients of the polynomial
        self.coefficients = curve_args.coefficients

        self.a = bin(curve_args.a)[2:]
        self.b = bin(curve_args.b)[2:]
        self.n = bin(curve_args.n)[2:]

        # irreducible polynomial
        self.fx = "".join(
            ["1" if i in self.coefficients else "0" for i in range(self.m, -1, -1)]
        )

        self.G = (bin(curve_args.G[0])[2:], bin(curve_args.G[1])[2:])
        assert (
            self.is_on_curve(self.G) is True
        ), f"Base point {self.G} is not on the curve!"

    def negative_point(self, P: Tuple[str, str]) -> Tuple[str, str]:
        """
        Returns the negative of the point P
            if P is (x, y), then -P is (x, -(x+y))
            for F2^n -x = x because of xor operation
        Args:
            P (tuple of str): Point on the curve
        Returns:
            -P (tuple of str): Negative of the point P
        """
        return (P[0], bin_ops.add(P[0], P[1]))

    def is_on_curve(self, P: Tuple[str, str]) -> bool:
        """
        Check if the point is on the curve
            y^2 + xy = x^3 + ax ^2 + b
        Args:
            P (tuple of str): Point on the curve
        Returns:
            result (bool): True if the point is on the curve, False otherwise
        """
        x, y = P

        return bin_ops.mod(
            bin_ops.add(
                bin_ops.square(y),
                bin_ops.multi(x, y),
            ),
            self.fx,
        ) == bin_ops.mod(
            bin_ops.add(
                bin_ops.add(
                    bin_ops.power_mod(x, 3, self.fx),
                    bin_ops.multi(self.a, bin_ops.square(x)),
                ),
                self.b,
            ),
            self.fx,
        )

    def add_points(self, P: Tuple[str, str], Q: Tuple[str, str]) -> Tuple[str, str]:
        """
        Add two points on the curve
        Args:
            P (tuple of str): Point on the curve
            Q (tuple of str): Point on the curve
        Returns:
            result (tuple of str): Result of the addition
        """
        if P == Q:
            return self.double_point(P)
        elif P == self.negative_point(Q):
            return self.O
        elif P == self.O:
            return Q
        elif Q == self.O:
            return P

        # ß = (y1-y2)/(x1-x2)
        beta = bin_ops.divide(
            a_bin=bin_ops.subtract(P[1], Q[1]),
            b_bin=bin_ops.subtract(P[0], Q[0]),
            p=self.fx,
        )
        x1, y1 = P
        x2, _ = Q

        # x3 = ß^2 + ß – x1 – x2 – a
        x3 = bin_ops.add(
            bin_ops.add(
                bin_ops.add(bin_ops.subtract(bin_ops.square(beta), beta), x1),
                x2,
            ),
            self.a,
        )

        # y3 = ß(x1 – x3) – x3 – y1
        y3 = bin_ops.add(
            bin_ops.subtract(bin_ops.multi(bin_ops.subtract(x1, x3), beta), x3),
            y1,
        )

        x3 = bin_ops.mod(x3, self.fx)
        y3 = bin_ops.mod(y3, self.fx)

        return (x3, y3)

    def double_point(self, P: Tuple[str, str]) -> Tuple[str, str]:
        """
        Returns double of the point P
        Args:
            P (tuple of str): Point on the curve
        Returns:
            2P (tuple of str): Double of the point P
        """
        if P == self.negative_point(P):
            return self.O

        x1, y1 = P

        # beta = x1 + (y1 / x1)
        beta = bin_ops.add(x1, bin_ops.divide(y1, x1, self.fx))

        # x2 = beta^2 + beta + a
        x2 = bin_ops.add(bin_ops.add(bin_ops.square(beta), beta), self.a)

        # y2 = x1^2 + beta * x2 + x2
        y2 = bin_ops.add(bin_ops.add(bin_ops.square(x1), bin_ops.multi(beta, x2)), x2)

        x2 = bin_ops.mod(x2, self.fx)
        y2 = bin_ops.mod(y2, self.fx)

        return (x2, y2)
