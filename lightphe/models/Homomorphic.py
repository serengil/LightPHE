# built-in dependencies
from typing import Optional, Union
from abc import ABC, abstractmethod

# 3rd party dependencies
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint

# project dependencies
from lightphe.models.Algorithm import Algorithm


# Signature for supported cryptosystems


class Homomorphic(ABC):
    keys: dict
    plaintext_modulo: int
    ciphertext_modulo: int

    @abstractmethod
    def generate_keys(
        self,
        key_size: int,
        s: Optional[int] = None,
        max_retries: Optional[int] = None,
        plaintext_limit: Optional[int] = None,
    ) -> dict:
        pass

    @abstractmethod
    def generate_random_key(self) -> int:
        pass

    @abstractmethod
    def encrypt(
        self, plaintext: int, random_key: Union[Optional[int], Optional[list]] = None
    ) -> Union[int, tuple, list, EllipticCurvePoint]:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: Union[int, tuple, list, EllipticCurvePoint]) -> int:
        pass

    def add(
        self,
        ciphertext1: Union[int, tuple, list, EllipticCurvePoint],
        ciphertext2: Union[int, tuple, list, EllipticCurvePoint],
    ) -> Union[int, tuple, list, EllipticCurvePoint]:
        raise ValueError(
            f"{self.get_algorithm_name()} is not homomorphic with respect to the addition"
        )

    def multiply(
        self,
        ciphertext1: Union[int, tuple, list, EllipticCurvePoint],
        ciphertext2: Union[int, tuple, list, EllipticCurvePoint],
    ) -> Union[int, tuple, list, EllipticCurvePoint]:
        raise ValueError(
            f"{self.get_algorithm_name()} is not homomorphic with respect to the multiplication"
        )

    def xor(
        self,
        ciphertext1: Union[int, tuple, list, EllipticCurvePoint],
        ciphertext2: Union[int, tuple, list, EllipticCurvePoint],
    ) -> Union[int, tuple, list, EllipticCurvePoint]:
        raise ValueError(
            f"{self.get_algorithm_name()} is not homomorphic with respect to the exclusive or"
        )

    def homomorphic_and(
        self,
        ciphertext1: Union[int, tuple, list, EllipticCurvePoint],
        ciphertext2: Union[int, tuple, list, EllipticCurvePoint],
    ) -> Union[int, tuple, list, EllipticCurvePoint]:
        raise ValueError(
            f"{self.get_algorithm_name()} is not homomorphic with respect to the bitwise and"
        )

    def multiply_by_constant(
        self, ciphertext: Union[int, tuple, list, EllipticCurvePoint], constant: int
    ) -> Union[int, tuple, list, EllipticCurvePoint]:
        raise ValueError(
            f"{self.get_algorithm_name()} is not supporting multiplying ciphertext by a known constant"
        )

    def reencrypt(
        self, ciphertext: Union[int, tuple, list, EllipticCurvePoint]
    ) -> Union[int, tuple, list, EllipticCurvePoint]:
        raise ValueError(f"{self.get_algorithm_name()} does not support re-encryption")

    def get_algorithm_name(self) -> str:
        class_name = self.__class__.__name__
        algorithm_name = getattr(Algorithm, class_name, None)
        assert isinstance(
            algorithm_name, str
        ), f"Algorithm name for {class_name} is not defined"
        return algorithm_name
