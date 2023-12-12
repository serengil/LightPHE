from typing import Union, List
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons import phe_utils


# TODO: add docstrings, validate private key is available in keys


# pylint: disable=too-few-public-methods
class EncryptedTensor:
    def __init__(
        self,
        dividend: Union[int, tuple, list],
        divisor: Union[int, tuple, list],
        sign: Union[int, tuple, list],
    ):
        self.dividend = dividend
        self.divisor = divisor
        self.sign = sign

    def __str__(self):
        return f"EncryptedTensor({self.sign} * {self.dividend} / {self.divisor})"

    def __repr__(self):
        return self.__str__()


class EncryptedTensors:
    def __init__(self, encrypted_tensor: List[EncryptedTensor], cs: Homomorphic):
        self.encrypted_tensor = encrypted_tensor
        self.cs = cs

    def __str__(self):
        results = []
        for i in self.encrypted_tensor:
            results.append(f"{i}")
        return ", ".join(results)

    def __repr__(self):
        return self.__str__()

    def __mul__(self, other: Union["EncryptedTensors", int, float]) -> "EncryptedTensors":
        if isinstance(other, EncryptedTensors) and len(self.encrypted_tensor) != len(
            other.encrypted_tensor
        ):
            raise ValueError("Tensor sizes must be equal in homomorphic multiplication")

        # TODO: cover scalar multiplication here

        current_tensors = []
        for i, alpha_tensor in enumerate(self.encrypted_tensor):
            beta_tensor = other.encrypted_tensor[i]

            current_dividend = self.cs.multiply(
                ciphertext1=alpha_tensor.dividend, ciphertext2=beta_tensor.dividend
            )
            current_divisor = self.cs.multiply(
                ciphertext1=alpha_tensor.divisor, ciphertext2=beta_tensor.divisor
            )

            current_tensor = EncryptedTensor(
                dividend=current_dividend, divisor=current_divisor, sign=1
            )

            current_tensors.append(current_tensor)

        return EncryptedTensors(encrypted_tensor=current_tensors, cs=self.cs)

    def __add__(self, other: "EncryptedTensors") -> "EncryptedTensors":
        if len(self.encrypted_tensor) != len(other.encrypted_tensor):
            raise ValueError("Tensor sizes must be equal")

        current_tensors = []
        for i, alpha_tensor in enumerate(self.encrypted_tensor):
            beta_tensor = other.encrypted_tensor[i]

            current_dividend = self.cs.add(
                ciphertext1=alpha_tensor.dividend, ciphertext2=beta_tensor.dividend
            )

            current_tensor = EncryptedTensor(
                dividend=current_dividend, divisor=alpha_tensor.divisor, sign=self.cs.encrypt(1)
            )

            current_tensors.append(current_tensor)

        return EncryptedTensors(encrypted_tensor=current_tensors, cs=self.cs)

    def __rmul__(self, constant: Union[int, float]) -> "EncryptedTensors":
        # TODO: write this method
        pass
