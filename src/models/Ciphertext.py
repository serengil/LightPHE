from typing import Union
from src.models.Homomorphic import Homomorphic
from src.models.Algorithm import Algorithm
from src.cryptosystems.RSA import RSA
from src.cryptosystems.ElGamal import ElGamal
from src.cryptosystems.Paillier import Paillier
from src.cryptosystems.DamgardJurik import DamgardJurik
from src.cryptosystems.OkamotoUchiyama import OkamotoUchiyama
from src.cryptosystems.Benaloh import Benaloh
from src.cryptosystems.NaccacheStern import NaccacheStern
from src.cryptosystems.GoldwasserMicali import GoldwasserMicali
from src.cryptosystems.EllipticCurveElGamal import EllipticCurveElGamal
from src.commons.logger import Logger

logger = Logger()

# pylint: disable=too-few-public-methods


class Ciphertext:
    def __init__(self, algorithm_name: str, keys: dict, value: Union[int, tuple, list]):
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
            cs = EllipticCurveElGamal(keys=keys)
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

    def __str__(self):
        return str(self.value)

    def __add__(self, other):
        """
        Perform homomorphic addition methods
        Args:
            other (Ciperhtext): its value will be added to self.value
        Returns:
            ciphertext (Ciphertext): self.value + other.value
        """
        result = self.cs.add(ciphertext1=self.value, ciphertext2=other.value)
        return Ciphertext(
            algorithm_name=self.algorithm_name, keys=self.keys, value=result
        )

    def __mul__(self, other):
        """
        Perform homomorphic multiplication or multiply a ciphertext with a known constant
        Args:
            other (int | Ciphertext)
        Returns
            self.value * other.value | self.value * other
        """
        if isinstance(other, Ciphertext):
            # Handle multiplication with another EncryptedObject
            result = self.cs.multiply(ciphertext1=self.value, ciphertext2=other.value)
        elif isinstance(other, int):
            result = self.cs.multiply_by_contant(ciphertext=self.value, constant=other)
        elif isinstance(other, float):
            decimal_places = len(str(other).split(".")[1])
            scaling_factor = 10**decimal_places
            integer_value = int(other * scaling_factor)

            if hasattr(self.cs, "modulo") and self.cs.modulo:
                modulo = self.cs.modulo
            elif hasattr(self.cs, "plaintext_modulo") and self.cs.plaintext_modulo:
                modulo = self.cs.plaintext_modulo
            else:
                raise ValueError(
                    "Cryptosystem must have either modulo or plaintext_modulo"
                )

            logger.debug(f"{integer_value}*{scaling_factor}^-1 mod {modulo}")

            constant = integer_value * pow(scaling_factor, -1, modulo)
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

    def __rmul__(self, constant):
        """
        Multiply a ciphertext with a known constant
        Args:
            constant (int)
        Returns
            self.value * constant
        """
        # Handle multiplication with a constant on the right
        result = self.cs.multiply_by_contant(ciphertext=self.value, constant=constant)
        return Ciphertext(
            algorithm_name=self.algorithm_name, keys=self.keys, value=result
        )

    def __xor__(self, other):
        """
        Perform homomorphic xor
        Args:
            other (int | Ciphertext)
        Returns
            self.value ^ other.value
        """
        result = self.cs.xor(ciphertext1=self.value, ciphertext2=other.value)
        return Ciphertext(
            algorithm_name=self.algorithm_name, keys=self.keys, value=result
        )
