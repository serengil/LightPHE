from typing import Union, Optional
from lightphe.models.Homomorphic import Homomorphic
from lightphe.models.Algorithm import Algorithm
from lightphe.cryptosystems.RSA import RSA
from lightphe.cryptosystems.ElGamal import ElGamal
from lightphe.cryptosystems.Paillier import Paillier
from lightphe.cryptosystems.DamgardJurik import DamgardJurik
from lightphe.cryptosystems.OkamotoUchiyama import OkamotoUchiyama
from lightphe.cryptosystems.Benaloh import Benaloh
from lightphe.cryptosystems.NaccacheStern import NaccacheStern
from lightphe.cryptosystems.GoldwasserMicali import GoldwasserMicali
from lightphe.cryptosystems.EllipticCurveElGamal import EllipticCurveElGamal
from lightphe.commons import phe_utils
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/models/Ciphertext.py")

# pylint: disable=too-few-public-methods, no-else-return


class Ciphertext:
    def __init__(
        self,
        algorithm_name: str,
        keys: dict,
        value: Union[int, tuple, list],
        form: Optional[str] = None,
        curve: Optional[str] = None,
    ):
        self.algorithm_name = algorithm_name
        self.keys = keys
        self.value = value

        if algorithm_name == Algorithm.RSA:
            cs = RSA(keys=keys)
        elif algorithm_name == Algorithm.ElGamal:
            cs = ElGamal(keys=keys)
        elif algorithm_name == Algorithm.ExponentialElGamal:
            cs = ElGamal(keys=keys, exponential=True)
        elif algorithm_name == Algorithm.EllipticCurveElGamal:
            cs = EllipticCurveElGamal(keys=keys, form=form, curve=curve)
        elif algorithm_name == Algorithm.Paillier:
            cs = Paillier(keys=keys)
        elif algorithm_name == Algorithm.DamgardJurik:
            cs = DamgardJurik(keys=keys)
        elif algorithm_name == Algorithm.OkamotoUchiyama:
            cs = OkamotoUchiyama(keys=keys)
        elif algorithm_name == Algorithm.Benaloh:
            cs = Benaloh(keys=keys)
        elif algorithm_name == Algorithm.NaccacheStern:
            cs = NaccacheStern(keys=keys)
        elif algorithm_name == Algorithm.GoldwasserMicali:
            cs = GoldwasserMicali(keys=keys)
        else:
            raise ValueError(f"unimplemented algorithm - {algorithm_name}")

        self.cs: Homomorphic = cs

    def __str__(self) -> str:
        return f"Ciphertext({self.value})"

    def __repr__(self) -> str:
        return f"Ciphertext({self.value})"

    def __add__(self, other: "Ciphertext") -> "Ciphertext":
        """
        Perform homomorphic addition methods
        Args:
            other (Ciperhtext): some other ciphertext
        Returns:
            ciphertext (Ciphertext): homomorphic addition of ciphertext
        """
        if self.cs.keys.get("public_key") is None:
            raise ValueError("You must have public key to perform homomorphic addition")

        result = self.cs.add(ciphertext1=self.value, ciphertext2=other.value)
        return Ciphertext(
            algorithm_name=self.algorithm_name, keys=self.keys, value=result
        )

    def __mul__(self, other: Union["Ciphertext", int, float]) -> "Ciphertext":
        """
        Perform homomorphic multiplication or multiply a ciphertext with a known constant
        Args:
            other (int | float | Ciphertext): a known plain constant of some other ciphertext
        Returns
            homomorphic multiplication of ciphertexts | scalar multiplication of ciphertext
        """
        if self.cs.keys.get("public_key") is None:
            raise ValueError(
                "You must have public key to perform homomorphic multiplication"
            )

        if isinstance(other, Ciphertext):
            # Handle multiplication with another EncryptedObject
            result = self.cs.multiply(ciphertext1=self.value, ciphertext2=other.value)
        elif isinstance(other, int):
            result = self.cs.multiply_by_contant(ciphertext=self.value, constant=other)
        elif isinstance(other, float):
            constant = phe_utils.normalize_input(
                value=other, modulo=self.cs.plaintext_modulo
            )
            result = self.cs.multiply_by_contant(
                ciphertext=self.value, constant=constant
            )
        else:
            raise ValueError(
                f"A ciphertext can be multiplied by either ciphertext itself or a scalar but it is {type(other)}"
            )
        return Ciphertext(
            algorithm_name=self.algorithm_name, keys=self.keys, value=result
        )

    def __rmul__(self, constant: Union[int, float]) -> "Ciphertext":
        """
        Multiply a ciphertext with a known constant
        Args:
            constant (int | float): a known plain constant
        Returns
            scalar multiplication of ciphertext
        """
        return self.__mul__(other=constant)

    def __xor__(self, other: "Ciphertext") -> "Ciphertext":
        """
        Perform homomorphic xor
        Args:
            other (| Ciphertext): some other ciphertext
        Returns
            homomorphic xor of ciphertexts
        """
        if self.cs.keys.get("public_key") is None:
            raise ValueError("You must have public key to perform homomorphic xor")

        result = self.cs.xor(ciphertext1=self.value, ciphertext2=other.value)
        return Ciphertext(
            algorithm_name=self.algorithm_name, keys=self.keys, value=result
        )
