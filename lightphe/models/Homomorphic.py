# built-in dependencies
from typing import Optional, Union, List, Tuple, Callable
from abc import ABC, abstractmethod

# 3rd party dependencies
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint

# project dependencies
from lightphe.models.Algorithm import Algorithm


# Signature for supported cryptosystems


# every cryptosystem implements a subset of these operations
# pylint: disable=too-many-public-methods
class Homomorphic(ABC):
    keys: dict
    plaintext_modulo: int
    ciphertext_modulo: int

    # Cryptosystems must define REQUIRED_KEYS as a dict with:
    #   - "public_key":  list of required sub-fields in keys["public_key"]
    #   - "private_key": list of required sub-fields in keys["private_key"]
    #   - "nested" (optional): dict mapping a public_key sub-field that itself
    #       holds a dict to its required sub-fields.
    #   - "alternative_private_key" (optional): list of sub-fields accepted in
    #       keys["private_key"] instead of the required ones.
    REQUIRED_KEYS: dict

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

    def encrypt_decision_tree_input(self, bits: List[int], depth: int) -> List[List[int]]:
        raise ValueError(
            f"{self.get_algorithm_name()} does not support evaluating decision trees"
            " with bits and depth"
        )

    def evaluate_decision_tree(
        self, tree: Union[int, tuple, list], encrypted_input: List[List[int]]
    ) -> Tuple[int, int]:
        raise ValueError(
            f"{self.get_algorithm_name()} does not support evaluating decision trees"
        )

    def encrypt_comparison_input(self, value: int, bit_length: int) -> List[int]:
        raise ValueError(f"{self.get_algorithm_name()} does not support secure comparison")

    def evaluate_comparison(self, encrypted_input: List[int], value: int) -> List[int]:
        raise ValueError(f"{self.get_algorithm_name()} does not support secure comparison")

    def decrypt_comparison(self, encrypted_result: List[int]) -> bool:
        raise ValueError(f"{self.get_algorithm_name()} does not support secure comparison")

    def encrypt_decision_tree_features(
        self, features: List[int], bit_length: int
    ) -> List[List[int]]:
        raise ValueError(
            f"{self.get_algorithm_name()} does not support private decision tree evaluation"
            " with features and bit_length"
        )

    def evaluate_decision_tree_comparisons(
        self, tree: Union[int, tuple], encrypted_features: List[List[int]]
    ) -> Tuple[List[List[int]], dict]:
        raise ValueError(
            f"{self.get_algorithm_name()} does not support private decision tree evaluation"
        )

    def answer_decision_tree_comparisons(
        self, encrypted_comparisons: List[List[int]]
    ) -> List[int]:
        raise ValueError(
            f"{self.get_algorithm_name()} does not support private decision tree evaluation"
        )

    def evaluate_decision_tree_leaves(
        self, server_state: dict, encrypted_answers: List[int]
    ) -> List[Tuple[int, int]]:
        raise ValueError(
            f"{self.get_algorithm_name()} does not support private decision tree evaluation"
        )

    def decrypt_decision_tree_output(
        self, encrypted_leaves: List[Tuple[int, int]]
    ) -> int:
        raise ValueError(
            f"{self.get_algorithm_name()} does not support private decision tree evaluation"
        )

    def evaluate_argmax(
        self,
        encrypted_values: List[int],
        bit_length: int,
        client: Callable[[dict], List[int]],
    ) -> int:
        raise ValueError(f"{self.get_algorithm_name()} does not support encrypted argmax")

    def answer_argmax(self, message: dict) -> List[int]:
        raise ValueError(f"{self.get_algorithm_name()} does not support encrypted argmax")

    def decrypt_with_master_key(
        self, ciphertext: Union[int, tuple, list, EllipticCurvePoint], public_key: Optional[dict] = None
    ) -> int:
        raise ValueError(
            f"{self.get_algorithm_name()} does not support master key decryption"
        )

    def generate_user_keys(self) -> dict:
        raise ValueError(
            f"{self.get_algorithm_name()} does not support generating user keys sharing a master key"
        )

    def encrypt_verifiably(self, secret: int, label: str = "") -> dict:
        raise ValueError(f"{self.get_algorithm_name()} does not support verifiable encryption")

    def verify_encryption(
        self,
        verifiable_ciphertext: dict,
        public_point: Union[tuple, EllipticCurvePoint],
        label: str = "",
    ) -> bool:
        raise ValueError(f"{self.get_algorithm_name()} does not support verifiable encryption")

    def decrypt_verifiable_ciphertext(self, verifiable_ciphertext: dict, label: str = "") -> int:
        raise ValueError(f"{self.get_algorithm_name()} does not support verifiable encryption")

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
