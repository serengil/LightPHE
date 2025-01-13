from typing import Tuple, Optional
from abc import ABC, abstractmethod

# Signature for elliptic curve


class EllipticCurve(ABC):
    p: Optional[int] = None
    fx: Optional[int] = None

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
