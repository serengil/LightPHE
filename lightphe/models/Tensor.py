# built-in dependencies
from typing import Union, List
import multiprocessing
from contextlib import closing

# 3rd party dependencies
from tqdm import tqdm

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons import phe_utils
from lightphe.models.Ciphertext import Ciphertext
from lightphe.models.Algorithm import Algorithm
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/models/Tensor.py")


# pylint: disable=too-few-public-methods, no-else-return
class Fraction:
    """
    Class to store fractional values
    """

    def __init__(
        self,
        dividend: Union[int, tuple, list],
        abs_dividend: Union[int, tuple, list],
        divisor: Union[int, tuple, list],
        sign: int = 1,
    ):
        self.dividend = dividend
        self.divisor = divisor
        self.sign = sign
        self.abs_dividend = abs_dividend

    def __str__(self):
        """
        Print Fraction Class Object
        """
        sign = "-" if self.sign == -1 else "+"
        return f"Fraction({sign}{self.abs_dividend} / {self.divisor})"

    def __repr__(self):
        """
        Print Fraction Class Object
        """
        return self.__str__()


class EncryptedTensor:
    """
    Class to store encrypted tensor objects
    """

    def __init__(
        self,
        fractions: List[Fraction],
        cs: Homomorphic,
        precision: int = 5,
    ):
        """
        Initialization method
        Args:
            fractions (list): list of fractions storing individual encrypted tensor items
            cs (cryptosystem): built cryptosystem
            precision (int): precision of the tensor
        """
        self.fractions = fractions
        self.cs = cs
        self.precision = precision

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

    def __matmul__(self, other: Union["EncryptedTensor", list]):
        """
        Perform dot product of two encrypted tensors
        """
        if not (
            (isinstance(other, EncryptedTensor) and isinstance(self, list))
            or (isinstance(other, list) and isinstance(self, EncryptedTensor))
        ):
            raise ValueError(
                "Dot product can be run for EncryptedTensor and List of float / int"
            )

        encrypted_tensor = self.__mul__(other=other)

        if len(encrypted_tensor.fractions) == 0:
            raise ValueError("Dot product cannot be calculated for empty tensor")

        divisor = cast_ciphertext(
            cs=self.cs, value=encrypted_tensor.fractions[0].divisor
        )

        if len(encrypted_tensor.fractions) > 10000:
            # parallelize the sum operation
            num_workers = min(
                len(encrypted_tensor.fractions), multiprocessing.cpu_count()
            )

            chunks = chunkify(encrypted_tensor.fractions, num_workers)

            with closing(multiprocessing.Pool(num_workers)) as pool:
                funclist = []

                for chunk in chunks:
                    f = pool.apply_async(sum_fractions_chunk, (chunk, self.cs))
                    funclist.append(f)

                partial_sums = []
                for f in tqdm(funclist, desc="Summing up fractions", disable=True):
                    result = f.get(timeout=10)
                    partial_sums.append(result)

            # map reduce
            total_sum = partial_sums[0]
            for partial in partial_sums[1:]:
                total_sum += partial

            fraction = Fraction(
                dividend=total_sum.value,
                abs_dividend=total_sum.value,
                divisor=divisor.value,
                sign=1,
            )
        else:
            # serial implementation
            sum_dividend = cast_ciphertext(
                cs=self.cs, value=encrypted_tensor.fractions[0].abs_dividend
            )
            divisor = cast_ciphertext(
                cs=self.cs, value=encrypted_tensor.fractions[0].divisor
            )

            if len(encrypted_tensor.fractions) > 1:
                for fraction in encrypted_tensor.fractions[1:]:
                    sum_dividend += cast_ciphertext(
                        value=fraction.abs_dividend, cs=self.cs
                    )

            fraction = Fraction(
                dividend=sum_dividend.value,
                abs_dividend=sum_dividend.value,
                divisor=divisor.value,
                sign=1,
            )

        return EncryptedTensor(fractions=[fraction], cs=self.cs)

    def __mul__(
        self, other: Union["EncryptedTensor", int, float, list]
    ) -> "EncryptedTensor":
        """
        Perform homomorphic element-wise multipliction on tensors
        or multiplication of an encrypted tensor with a constant
        Args:
            other: encrypted tensor or constant
        Returns:
            encrypted tensor
        """
        if isinstance(other, EncryptedTensor):
            if isinstance(other, EncryptedTensor) and len(self.fractions) != len(
                other.fractions
            ):
                raise ValueError(
                    "Tensor sizes must be equal in homomorphic multiplication"
                )

            fractions = []
            for i, alpha_tensor in enumerate(self.fractions):
                beta_tensor = other.fractions[i]

                current_dividend = self.cs.multiply(
                    ciphertext1=alpha_tensor.dividend, ciphertext2=beta_tensor.dividend
                )

                current_abs_dividend = self.cs.multiply(
                    ciphertext1=alpha_tensor.abs_dividend,
                    ciphertext2=beta_tensor.abs_dividend,
                )

                current_divisor = self.cs.multiply(
                    ciphertext1=alpha_tensor.divisor, ciphertext2=beta_tensor.divisor
                )

                fraction = Fraction(
                    dividend=current_dividend,
                    abs_dividend=current_abs_dividend,
                    divisor=current_divisor,
                    sign=alpha_tensor.sign * beta_tensor.sign,
                )

                fractions.append(fraction)

            return EncryptedTensor(fractions=fractions, cs=self.cs)

        elif isinstance(other, list):
            # perform element-wise multiplication of encrypted tensor with plain tensor
            if len(self.fractions) != len(other):
                raise ValueError(
                    "Tensor sizes must be equal in homomorphic multiplication"
                )

            if any(i < 0 for i in other) or any(
                fraction.sign < 0 for fraction in self.fractions
            ):
                raise ValueError(
                    "all items in the plain and encrypted tensor must be positive"
                    " to perform element wise multiplication"
                )

            dividends = []
            divisor = None
            for alpha, beta in zip(self.fractions, other):
                c_abs_dividend, c_divisor = phe_utils.fractionize(
                    value=(
                        abs(beta) % self.cs.plaintext_modulo
                        if abs(beta) > self.cs.plaintext_modulo
                        else abs(beta)
                    ),
                    modulo=self.cs.plaintext_modulo,
                    precision=self.precision,
                )

                dividend = (
                    cast_ciphertext(cs=self.cs, value=alpha.abs_dividend)
                    * c_abs_dividend
                )

                if divisor is None:
                    divisor = (
                        cast_ciphertext(cs=self.cs, value=alpha.divisor) * c_divisor
                    )

                # dividends.append(dividend)
                dividends.append(
                    Fraction(
                        dividend=dividend.value,
                        abs_dividend=dividend.value,
                        divisor=divisor.value,
                        sign=1,
                    )
                )

            return EncryptedTensor(fractions=dividends, cs=self.cs)

        elif isinstance(other, (int, float)):
            constant_sign = 1 if other >= 0 else -1
            other = abs(other)
            if isinstance(other, float):
                other = phe_utils.normalize_input(
                    value=other, modulo=self.cs.plaintext_modulo
                )

            fractions = []
            for alpha_tensor in self.fractions:
                dividend = self.cs.multiply_by_constant(
                    ciphertext=alpha_tensor.dividend, constant=other
                )
                abs_dividend = self.cs.multiply_by_constant(
                    ciphertext=alpha_tensor.abs_dividend, constant=other
                )
                # notice that divisor is alpha tensor's divisor instead of addition
                fraction = Fraction(
                    dividend=dividend,
                    abs_dividend=abs_dividend,
                    divisor=alpha_tensor.divisor,
                    sign=constant_sign * alpha_tensor.sign,
                )
                fractions.append(fraction)
            return EncryptedTensor(fractions=fractions, cs=self.cs)
        else:
            raise ValueError(
                "Encrypted tensor can be multiplied by an encrypted tensor or constant"
            )

    def __rmul__(
        self, multiplier: Union[int, float, "EncryptedTensor"]
    ) -> "EncryptedTensor":
        """
        Perform multiplication of encrypted tensor with a constant or plain tensor (element-wise)
        Args:
            multiplier: scalar value
        Returns:
            encrypted tensor
        """
        return self.__mul__(other=multiplier)

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
            current_abs_dividend = self.cs.add(
                ciphertext1=alpha_tensor.abs_dividend,
                ciphertext2=beta_tensor.abs_dividend,
            )
            # notice that divisor is alpha tensor's divisor instead of addition
            if alpha_tensor.sign == -1 and beta_tensor.sign == -1:
                current_tensor = Fraction(
                    dividend=current_dividend,
                    abs_dividend=current_abs_dividend,
                    divisor=alpha_tensor.divisor,
                    sign=-1,
                )
            else:
                # if one is positive and one is negative, then i cannot know
                # the result is positive or negative. trust mod calculations.
                if alpha_tensor.sign != beta_tensor.sign:
                    logger.warn(
                        f"{i}-th items of the vectors have different signs, and result's sign "
                        "cannot be determined in PHE. Result will be shown for positive for this anyway."
                    )

                current_tensor = Fraction(
                    dividend=current_dividend,
                    abs_dividend=current_dividend,
                    divisor=alpha_tensor.divisor,
                    sign=1,
                )

            current_tensors.append(current_tensor)

        return EncryptedTensor(fractions=current_tensors, cs=self.cs)


def cast_ciphertext(cs: Homomorphic, value: int) -> Ciphertext:
    """Cast an integer value to a Ciphertext object."""

    class_name = cs.__class__.__name__
    algorithm_name = getattr(Algorithm, class_name, None)

    assert algorithm_name is not None, f"Algorithm name not found for {class_name}"

    return Ciphertext(
        algorithm_name=algorithm_name,
        keys=cs.keys,
        value=value,
        form=cs.keys.get("form"),
        curve=cs.keys.get("curve"),
    )


def chunkify(lst: list, n: int):
    """Split list into n approximately equal chunks."""
    avg = len(lst) // n
    remainder = len(lst) % n
    chunks = []
    start = 0
    for i in range(n):
        end = start + avg + (1 if i < remainder else 0)
        chunks.append(lst[start:end])
        start = end
    return chunks


def sum_fractions_chunk(fractions_chunk: list, cs: Homomorphic):
    """Compute the sum of a chunk of fractions in parallel."""
    result = cast_ciphertext(cs=cs, value=fractions_chunk[0].abs_dividend)
    for fraction in fractions_chunk[1:]:
        result += cast_ciphertext(cs=cs, value=fraction.abs_dividend)
    return result
