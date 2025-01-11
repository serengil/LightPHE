# built-in dependencies
from abc import ABC
from typing import Tuple, List


# pylint: disable=too-few-public-methods
class WeierstrassInterface(ABC):
    p: int  # modulo
    a: int  # equation parameters
    b: int  # equation parameters
    G: Tuple[int, int]  # base point G
    n: int  # elliptic curve order (number of points on the curve)


class TwistedEdwardsInterface(ABC):
    p: int  # modulo
    a: int  # equation parameters
    d: int  # equation parameters
    G: Tuple[int, int]  # base point G
    n: int  # elliptic curve order (number of points on the curve)


class KoblitzInterface(ABC):
    m: int  # degree of the irreducible polynomial
    coefficients: List[int]  # coefficients of the polynomial
    a: int  # equation parameters
    b: int  # equation parameters
    G: Tuple[int, int]  # base point G
    n: int  # elliptic curve order (number of points on the curve)
