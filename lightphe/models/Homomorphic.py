from typing import Optional, Union
from abc import ABC, abstractmethod

# Signature for supported cryptosystems


class Homomorphic(ABC):
    keys: dict
    plaintext_modulo: int
    ciphertext_modulo: int

    @abstractmethod
    def generate_keys(self, key_size: int, s: Optional[int] = None) -> dict:
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

    @abstractmethod
    def add(
        self, ciphertext1: Union[int, tuple, list], ciphertext2: Union[int, tuple, list]
    ) -> Union[int, tuple, list]:
        pass

    @abstractmethod
    def multiply(
        self, ciphertext1: Union[int, tuple, list], ciphertext2: Union[int, tuple, list]
    ) -> Union[int, tuple]:
        pass

    @abstractmethod
    def xor(self, ciphertext1: list, ciphertext2: list) -> list:
        pass

    @abstractmethod
    def multiply_by_contant(self, ciphertext: Union[int, tuple, list], constant: int) -> int:
        pass

    @abstractmethod
    def reencrypt(self, ciphertext: Union[int, tuple, list]) -> Union[int, tuple, list]:
        pass
