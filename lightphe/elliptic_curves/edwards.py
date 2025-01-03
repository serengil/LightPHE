# built-in dependencies
from abc import ABC
from typing import Tuple


class TwistedEdwards(ABC):
    p: int  # modulo
    a: int  # equation parameters
    d: int  # equation parameters
    G: Tuple[int, int]  # base point G
    n: int  # elliptic curve order (number of points on the curve)
