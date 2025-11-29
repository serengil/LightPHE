# built-in dependencies
from typing import Optional, Union
from abc import ABC, abstractmethod

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
    ) -> Union[int, tuple, list]:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: Union[int, tuple, list]) -> int:
        pass

    def add(
        self, ciphertext1: Union[int, tuple, list], ciphertext2: Union[int, tuple, list]
    ) -> Union[int, tuple, list]:
        raise ValueError(
            f"{self.get_algorithm_name()} is not homomorphic with respect to the addition"
        )

    def multiply(
        self, ciphertext1: Union[int, tuple, list], ciphertext2: Union[int, tuple, list]
    ) -> Union[int, tuple]:
        raise ValueError(
            f"{self.get_algorithm_name()} is not homomorphic with respect to the multiplication"
        )

    def xor(self, ciphertext1: list, ciphertext2: list) -> list:
        raise ValueError(
            f"{self.get_algorithm_name()} is not homomorphic with respect to the exclusive or"
        )

    def multiply_by_constant(
        self, ciphertext: Union[int, tuple, list], constant: int
    ) -> int:
        raise ValueError(
            f"{self.get_algorithm_name()} is not supporting multiplying ciphertext by a known constant"
        )

    def reencrypt(self, ciphertext: Union[int, tuple, list]) -> Union[int, tuple, list]:
        raise ValueError(f"{self.get_algorithm_name()} does not support re-encryption")

    def get_algorithm_name(self) -> str:
        class_name = self.__class__.__name__
        algorithm_name = getattr(Algorithm, class_name, None)
        assert isinstance(
            algorithm_name, str
        ), f"Algorithm name for {class_name} is not defined"
        return algorithm_name
