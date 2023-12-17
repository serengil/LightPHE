from typing import Union, List
from lightphe.models.Homomorphic import Homomorphic


# TODO: add docstrings, validate private key is available in keys


# pylint: disable=too-few-public-methods
class Fraction:
    def __init__(
        self,
        dividend: Union[int, tuple, list],
        abs_dividend: Union[int, tuple, list],
        divisor: Union[int, tuple, list],
        sign: int,
    ):
        self.dividend = dividend
        self.abs_dividend = abs_dividend
        self.divisor = divisor
        self.sign = sign

    def __str__(self):
        return f"EncryptedTensor({self.sign} * {self.dividend} / {self.divisor})"

    def __repr__(self):
        return self.__str__()


class EncryptedTensor:
    def __init__(self, fractions: List[Fraction], cs: Homomorphic):
        self.fractions = fractions
        self.cs = cs

    def __str__(self):
        results = []
        for i in self.fractions:
            results.append(f"{i}")
        return ", ".join(results)

    def __repr__(self):
        return self.__str__()

    def __mul__(self, other: Union["EncryptedTensor", int, float]) -> "EncryptedTensor":
        if isinstance(other, EncryptedTensor) and len(self.fractions) != len(other.fractions):
            raise ValueError("Tensor sizes must be equal in homomorphic multiplication")

        # TODO: cover scalar multiplication here

        fractions = []
        for i, alpha_tensor in enumerate(self.fractions):
            beta_tensor = other.fractions[i]

            current_dividend = self.cs.multiply(
                ciphertext1=alpha_tensor.abs_dividend, ciphertext2=beta_tensor.dividend
            )

            current_divisor = self.cs.multiply(
                ciphertext1=alpha_tensor.divisor, ciphertext2=beta_tensor.divisor
            )

            fraction = Fraction(
                dividend=current_dividend,
                abs_dividend=current_dividend,
                divisor=current_divisor,
                sign=alpha_tensor.sign * beta_tensor.sign,
            )

            fractions.append(fraction)

        return EncryptedTensor(fractions=fractions, cs=self.cs)

    def __add__(self, other: "EncryptedTensor") -> "EncryptedTensor":
        if len(self.fractions) != len(other.fractions):
            raise ValueError("Fraction sizes must be equal")

        current_tensors = []
        for i, alpha_tensor in enumerate(self.fractions):
            beta_tensor = other.fractions[i]

            current_dividend = self.cs.add(
                ciphertext1=alpha_tensor.dividend, ciphertext2=beta_tensor.dividend
            )

            current_tensor = Fraction(
                dividend=current_dividend,
                abs_dividend=current_dividend,
                divisor=alpha_tensor.divisor,
                sign=1,
            )

            current_tensors.append(current_tensor)

        return EncryptedTensor(fractions=current_tensors, cs=self.cs)
