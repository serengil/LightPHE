from typing import Union, List
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons import phe_utils


# pylint: disable=too-few-public-methods, no-else-return
class Fraction:
    """
    Class to store fractional values
    """

    def __init__(
        self,
        dividend: Union[int, tuple, list],
        divisor: Union[int, tuple, list],
    ):
        self.dividend = dividend
        self.divisor = divisor

    def __str__(self):
        """
        Print Fraction Class Object
        """
        return f"Fraction({self.dividend} / {self.divisor})"

    def __repr__(self):
        """
        Print Fraction Class Object
        """
        return self.__str__()


class EncryptedTensor:
    """
    Class to store encrypted tensor objects
    """

    def __init__(self, fractions: List[Fraction], cs: Homomorphic):
        """
        Initialization method
        Args:
            fractions (list): list of fractions storing individual encrypted tensor items
            cs: cryptosystem
        """
        self.fractions = fractions
        self.cs = cs

    def __str__(self):
        """
        Print encrypted tensor object
        """
        results = []
        for i in self.fractions:
            results.append(f"{i}")
        return ", ".join(results)

    def __repr__(self):
        """
        Print encrypted tensor object
        """
        return self.__str__()

    def __mul__(self, other: Union["EncryptedTensor", int, float]) -> "EncryptedTensor":
        """
        Perform homomorphic multipliction on tensors or multiplication of an encrypted tensor with a constant
        Args:
            other: encrypted tensor or constant
        Returns:
            encrypted tensor
        """
        if isinstance(other, EncryptedTensor):
            if isinstance(other, EncryptedTensor) and len(self.fractions) != len(other.fractions):
                raise ValueError("Tensor sizes must be equal in homomorphic multiplication")

            fractions = []
            for i, alpha_tensor in enumerate(self.fractions):
                beta_tensor = other.fractions[i]

                current_dividend = self.cs.multiply(
                    ciphertext1=alpha_tensor.dividend, ciphertext2=beta_tensor.dividend
                )

                current_divisor = self.cs.multiply(
                    ciphertext1=alpha_tensor.divisor, ciphertext2=beta_tensor.divisor
                )

                fraction = Fraction(
                    dividend=current_dividend,
                    divisor=current_divisor,
                )

                fractions.append(fraction)

            return EncryptedTensor(fractions=fractions, cs=self.cs)
        elif isinstance(other, (int, float)):
            if isinstance(other, float):
                other = phe_utils.parse_int(value=other, modulo=self.cs.plaintext_modulo)

            fractions = []
            for alpha_tensor in self.fractions:
                dividend = self.cs.multiply_by_contant(
                    ciphertext=alpha_tensor.dividend, constant=other
                )
                # notice that divisor is alpha tensor's divisor instead of addition
                fraction = Fraction(
                    dividend=dividend,
                    divisor=alpha_tensor.divisor,
                )
                fractions.append(fraction)
            return EncryptedTensor(fractions=fractions, cs=self.cs)
        else:
            raise ValueError(
                "Encrypted tensor can be multiplied by an encrypted tensor or constant"
            )

    def __rmul__(self, constant: Union[int, float]) -> "EncryptedTensor":
        """
        Perform multiplication of encrypted tensor with a constant
        Args:
            constant: scalar value
        Returns:
            encrypted tensor
        """
        return self.__mul__(other=constant)

    def __add__(self, other: "EncryptedTensor") -> "EncryptedTensor":
        """
        Perform homomorphic addition
        Args:
            other: encrypted tensor
        Returns:
            encrypted tensor
        """
        if len(self.fractions) != len(other.fractions):
            raise ValueError("Fraction sizes must be equal")

        current_tensors = []
        for i, alpha_tensor in enumerate(self.fractions):
            beta_tensor = other.fractions[i]

            current_dividend = self.cs.add(
                ciphertext1=alpha_tensor.dividend, ciphertext2=beta_tensor.dividend
            )
            # notice that divisor is alpha tensor's divisor instead of addition
            current_tensor = Fraction(
                dividend=current_dividend,
                divisor=alpha_tensor.divisor,
            )

            current_tensors.append(current_tensor)

        return EncryptedTensor(fractions=current_tensors, cs=self.cs)
