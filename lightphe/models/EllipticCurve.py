# built-in dependencies
from typing import Tuple
from abc import ABC, abstractmethod

# project dependencies
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/models/EllipticCurve.py")

# Signature for elliptic curve


class EllipticCurve(ABC):
    # point at infinity or neutral / identity element
    O: Tuple[int, int]

    # base point G
    G: Tuple[int, int]

    # modulo (prime p or polynomial fx)
    modulo: int

    # order of the curve
    n: int

    # coefficients
    a: int
    b: int = 0  # for weierstrass & koblitz form
    d: int = 0  # for edwards form

    @abstractmethod
    def add_points(
        self,
        P: Tuple[int, int],
        Q: Tuple[int, int],
    ) -> Tuple[int, int]:
        pass

    @abstractmethod
    def double_point(self, P: Tuple[int, int]) -> Tuple[int, int]:
        pass

    @abstractmethod
    def is_on_curve(self, P: Tuple[int, int]) -> bool:
        pass

    @abstractmethod
    def negative_point(self, P: Tuple[int, int]) -> Tuple[int, int]:
        pass

    def double_and_add(self, G: Tuple[int, int], k: int) -> Tuple[int, int]:
        """
        Perform scalar multiplication over elliptic curve
        Args:
            G (Tuple[int, int]): a point on an elliptic curve
            k (int): scalar value
        Returns
            kxG (Tuple[int, int]): a point on an elliptic curve
        """
        target_point = G

        if k >= self.n:
            k = k % self.n
        if k == 0:
            return self.O
        if k < 0:
            return self.negative_point(self.double_and_add(G, abs(k)))

        k_binary = bin(k)[2:]

        for i in range(1, len(k_binary)):
            current_bit = k_binary[i : i + 1]

            # doubling - always
            target_point = self.double_point(target_point)

            if current_bit == "1":
                target_point = self.add_points(target_point, G)

        assert (
            self.is_on_curve(target_point) is True
        ), f"{target_point} is not on the curve!"

        return target_point


class EllipticCurvePoint:
    """
    Define a point on an elliptic curve
    """

    def __init__(self, x: int, y: int, curve: EllipticCurve):
        self.x = x
        self.y = y
        self.curve = curve

        assert self.curve.is_on_curve((x, y)), f"({x}, {y}) is not on the curve!"

    def get_point(self) -> Tuple[int, int]:
        return (self.x, self.y)

    def __repr__(self):

        if (
            self.x == self.curve.O[0]
            and self.y == self.curve.O[1]
            and self.x == float("inf")
            and self.y == float("inf")
        ):
            # because Edwards has neutral / identity element instead of point at infinity
            return "\U0001D4AA"  # unicode for "𝒪" (circle O)
        return f"({self.x}, {self.y})"

    def __str__(self):
        return self.__repr__()

    def __add__(self, other: "EllipticCurvePoint") -> "EllipticCurvePoint":
        """
        Calculate P + Q for two given points P and Q
        """
        if not isinstance(other, EllipticCurvePoint):
            raise ValueError("Addition is only defined for 2 points")

        if self.curve != other.curve:
            raise ValueError("Points are not on the same curve")

        x, y = self.curve.add_points((self.x, self.y), (other.x, other.y))
        return EllipticCurvePoint(x, y, self.curve)

    def __sub__(self, other: "EllipticCurvePoint") -> "EllipticCurvePoint":
        """
        Calculate P - Q for two given points P and Q
        """
        return self.__add__(other=other.__neg__())

    def __mul__(self, k: int) -> "EllipticCurvePoint":
        """
        Calculate k*P for a given k and P
        """
        if not isinstance(k, int):
            raise ValueError("Multiplication is only defined for an integer")

        x, y = self.curve.double_and_add((self.x, self.y), k)
        return EllipticCurvePoint(x, y, self.curve)

    def __rmul__(self, k: int) -> "EllipticCurvePoint":
        """
        Calculate k*P for a given k and P
        """
        if not isinstance(k, int):
            raise ValueError("Multiplication is only defined for an integer")
        return self.__mul__(k)

    def __neg__(self) -> "EllipticCurvePoint":
        """
        Calculate -P for a given P
        """
        x, y = self.curve.negative_point((self.x, self.y))
        return EllipticCurvePoint(x, y, self.curve)

    def __eq__(self, other: "EllipticCurvePoint") -> bool:
        """
        Check if two points are equal
        """
        return self.x == other.x and self.y == other.y and self.curve == other.curve

    def __truediv__(self, other: "EllipticCurvePoint") -> int:
        """
        Resolve ECDLP - this is a hard problem!
        """
        # TODO: you may consider to use baby-step-giant-step instead of brute force

        logger.debug(f"Find k from ({self.x}, {self.y}) = k x ({other.x}, {other.y})")

        ox, oy = self.curve.O
        if self.x == other.x and self.y == other.y:
            return 1
        if self.x == ox and self.y == oy:
            return self.curve.n

        # base point
        gx, gy = self.curve.G

        k = 2
        while True:
            kG = self.curve.double_and_add((gx, gy), k)

            if kG[0] == self.x and kG[1] == self.y:
                return k

            k = k + 1

            if k > self.curve.n:
                raise ValueError(
                    f"Cannot restore scalar from ({self.x}, {self.y}) = k x ({other.x}, {other.y})"
                )
