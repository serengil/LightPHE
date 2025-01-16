from typing import Tuple
from abc import ABC, abstractmethod

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
