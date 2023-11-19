from typing import Tuple
from abc import ABC, abstractmethod

# Signature for elliptic curve


class EllipticCurve(ABC):
    @abstractmethod
    def add_points(self, P: Tuple[int, int], Q: Tuple[int, int], p: int) -> Tuple[int, int]:
        pass

    @abstractmethod
    def apply_double_and_add_method(self, G: Tuple[int, int], k: int, p: int) -> Tuple[int, int]:
        pass

    @abstractmethod
    def is_on_curve(self, P: Tuple[int, int], p: int):
        pass
