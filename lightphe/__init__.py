import json
from typing import Optional, Union, List

from lightphe.models.Homomorphic import Homomorphic
from lightphe.models.Ciphertext import Ciphertext
from lightphe.models.Algorithm import Algorithm
from lightphe.models.Tensor import Fraction, EncryptedTensor
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

# pylint: disable=eval-used, simplifiable-if-expression

logger = Logger(module="lightphe/__init__.py")


class LightPHE:
    def __init__(
        self,
        algorithm_name: str,
        keys: Optional[dict] = None,
        key_file: Optional[str] = None,
        key_size: Optional[int] = None,
        precision: int = 5,
    ):
        """
        Build LightPHE class
        Args:
            algorithm_name (str): RSA | ElGamal | Exponential-ElGamal | EllipticCurve-ElGamal
                | Paillier | Damgard-Jurik | Okamoto-Uchiyama | Benaloh | Naccache-Stern
                | Goldwasser-Micali
            keys (dict): optional private-public key pair
            key_file (str): if keys are exported, you can load them into cryptosystem
            key_size (int): key size in bits
            precision (int): precision for homomorphic operations on tensors
        """
        self.algorithm_name = algorithm_name
        self.precision = precision

        if key_file is not None:
            keys = self.restore_keys(target_file=key_file)

        self.cs: Homomorphic = self.__build_cryptosystem(
            algorithm_name=algorithm_name, keys=keys, key_size=key_size
        )

    def __build_cryptosystem(
        self,
        algorithm_name: str,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
    ) -> Union[
        RSA,
        ElGamal,
        Paillier,
        DamgardJurik,
        OkamotoUchiyama,
        Benaloh,
        NaccacheStern,
        EllipticCurveElGamal,
    ]:
        """
        Build a cryptosystem among partially homomorphic algorithms
        Args:
            algorithm_name (str): RSA | ElGamal | Exponential-ElGamal | EllipticCurve-ElGamal
                | Paillier | Damgard-Jurik | Okamoto-Uchiyama | Benaloh | Naccache-Stern
                | Goldwasser-Micali
            keys (dict): optional private-public key pair
            key_file (str): if keys are exported, you can load them into cryptosystem
            key_size (int): key size in bits
        Returns
            cryptosystem
        """

        if key_size is None:
            key_size = self.recommend_key_size(algorithm_name=algorithm_name)

        # build cryptosystem
        if algorithm_name == Algorithm.RSA:
            cs = RSA(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.ElGamal:
            cs = ElGamal(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.ExponentialElGamal:
            cs = ElGamal(keys=keys, key_size=key_size, exponential=True)
        elif algorithm_name == Algorithm.EllipticCurveElGamal:
            cs = EllipticCurveElGamal(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.Paillier:
            cs = Paillier(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.DamgardJurik:
            cs = DamgardJurik(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.OkamotoUchiyama:
            cs = OkamotoUchiyama(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.Benaloh:
            cs = Benaloh(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.NaccacheStern:
            cs = NaccacheStern(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.GoldwasserMicali:
            cs = GoldwasserMicali(keys=keys, key_size=key_size)
        else:
            raise ValueError(f"unimplemented algorithm - {algorithm_name}")
        return cs

    def encrypt(self, plaintext: Union[int, float, list]) -> Union[Ciphertext, EncryptedTensor]:
        """
        Encrypt a plaintext with a built cryptosystem
        Args:
            plaintext (int, float or tensor): message
        Returns
            ciphertext (from lightphe.models.Ciphertext import Ciphertext): encrypted message
        """
        if self.cs.keys.get("public_key") is None:
            raise ValueError("You must have public key to perform encryption")

        if isinstance(plaintext, list):
            # then encrypt tensors
            return self.__encrypt_tensors(tensor=plaintext)

        ciphertext = self.cs.encrypt(
            plaintext=phe_utils.parse_int(value=plaintext, modulo=self.cs.plaintext_modulo)
        )
        return Ciphertext(algorithm_name=self.algorithm_name, keys=self.cs.keys, value=ciphertext)

    def decrypt(
        self, ciphertext: Union[Ciphertext, EncryptedTensor]
    ) -> Union[int, List[int], List[float]]:
        """
        Decrypt a ciphertext with a buit cryptosystem
        Args:
            ciphertext (from lightphe.models.Ciphertext import Ciphertext): encrypted message
        Returns:
            plaintext (int): restored message
        """
        if self.cs.keys.get("private_key") is None:
            raise ValueError("You must have private key to perform decryption")

        if self.cs.keys.get("public_key") is None:
            raise ValueError("You must have public key to perform decryption")

        if isinstance(ciphertext, EncryptedTensor):
            # then this is encrypted tensor
            return self.__decrypt_tensors(encrypted_tensor=ciphertext)

        return self.cs.decrypt(ciphertext=ciphertext.value)

    def __encrypt_tensors(self, tensor: list) -> EncryptedTensor:
        """
        Encrypt a given tensor
        Args:
            tensor (list of int or float)
        Returns
            encrypted tensor (list of encrypted tensor object)
        """
        encrypted_tensor: List[Fraction] = []
        for m in tensor:
            if isinstance(m, int):
                dividend_encrypted = self.cs.encrypt(
                    plaintext=(m % self.cs.plaintext_modulo) * pow(10, self.precision)
                )
                abs_dividend_encrypted = self.cs.encrypt(
                    plaintext=(abs(m) % self.cs.plaintext_modulo) * pow(10, self.precision)
                )
                divisor_encrypted = self.cs.encrypt(plaintext=pow(10, self.precision))
                c = Fraction(
                    dividend=dividend_encrypted,
                    divisor=divisor_encrypted,
                    abs_dividend=abs_dividend_encrypted,
                    sign=1 if m >= 0 else -1,
                )
            elif isinstance(m, float):
                dividend, divisor = phe_utils.fractionize(
                    value=(m % self.cs.plaintext_modulo),
                    modulo=self.cs.plaintext_modulo,
                    precision=self.precision,
                )
                abs_dividend, _ = phe_utils.fractionize(
                    value=(abs(m) % self.cs.plaintext_modulo),
                    modulo=self.cs.plaintext_modulo,
                    precision=self.precision,
                )
                dividend_encrypted = self.cs.encrypt(plaintext=dividend)
                abs_dividend_encrypted = self.cs.encrypt(plaintext=abs_dividend)
                divisor_encrypted = self.cs.encrypt(plaintext=divisor)
                c = Fraction(
                    dividend=dividend_encrypted,
                    divisor=divisor_encrypted,
                    abs_dividend=abs_dividend_encrypted,
                    sign=1 if m >= 0 else -1,
                )
            else:
                raise ValueError(f"unimplemented type - {type(m)}")
            encrypted_tensor.append(c)
        return EncryptedTensor(fractions=encrypted_tensor, cs=self.cs)

    def __decrypt_tensors(self, encrypted_tensor: EncryptedTensor) -> Union[List[int], List[float]]:
        """
        Decrypt a given encrypted tensor
        Args:
            encrypted_tensor (list of encrypted tensor)
        Returns:
            List of plain tensors
        """
        plain_tensor = []
        for c in encrypted_tensor.fractions:
            if isinstance(c, Fraction) is False:
                raise ValueError("Ciphertext items must be type of Fraction")

            sign = c.sign
            abs_dividend = self.cs.decrypt(ciphertext=c.abs_dividend)
            # dividend = self.cs.decrypt(ciphertext=c.dividend)
            divisor = self.cs.decrypt(ciphertext=c.divisor)
            m = sign * abs_dividend / divisor

            plain_tensor.append(m)
        return plain_tensor

    def regenerate_ciphertext(self, ciphertext: Ciphertext) -> Ciphertext:
        """
        Generate a different ciphertext belonging to same plaintext
        Args:
            ciphertext (from lightphe.models.Ciphertext import Ciphertext): encrypted message
        Returns:
            ciphertext (from lightphe.models.Ciphertext import Ciphertext): encrypted message
        """
        if self.cs.keys.get("private_key") is None:
            raise ValueError("You must have private key to perform decryption")

        ciphertext_new = self.cs.reencrypt(ciphertext=ciphertext.value)
        return Ciphertext(
            algorithm_name=self.algorithm_name, keys=self.cs.keys, value=ciphertext_new
        )

    def export_keys(self, target_file: str, public: bool = False) -> None:
        """
        Export keys to a file
        Args:
            target_file (str): target file name
            public (bool): set this to True if you will publish this
                to publicly.
        """
        keys = self.cs.keys
        private_key = None
        if public is True and keys.get("private_key") is not None:
            private_key = keys["private_key"]
            del keys["private_key"]

        if public is False:
            logger.warn(
                "You did not set public arg to True. So, exported key has private key information."
                "Do not share this to anyone"
            )

        with open(target_file, "w", encoding="UTF-8") as file:
            file.write(json.dumps(keys))

        # restore private key if you dropped
        if private_key is not None:
            self.cs.keys["private_key"] = private_key

    def restore_keys(self, target_file: str) -> dict:
        """
        Restore keys from a file
        Args:
            target_file (str): target file name
        Returns:
            keys (dict): private public key pair
        """
        with open(target_file, "r", encoding="UTF-8") as file:
            dict_str = file.read()

        keys = eval(dict_str)
        if not isinstance(keys, dict):
            raise ValueError(
                f"The content of the file {target_file} does not represent a valid dictionary."
            )

        if "private_key" in keys.keys():
            logger.info(f"private-public key pair is restored from {target_file}")
        elif "public_key" in keys.keys():
            logger.info(f"public key is restored from {target_file}")
        else:
            raise ValueError(f"File {target_file} must have public_key key")
        return keys

    def recommend_key_size(self, algorithm_name: str) -> int:
        """
        Recommend a key size in bits if it is not mentioned by the user
        Args:
            algorithm_name (str): algorithm name
        Returns
            key_size (int)
        """
        if algorithm_name == Algorithm.RSA:
            key_size = 1024
        elif algorithm_name == Algorithm.ElGamal:
            key_size = 1024
        elif algorithm_name == Algorithm.ExponentialElGamal:
            key_size = 1024
        # 160-bit ECC is equivalent to 1024-bit RSA
        elif algorithm_name == Algorithm.EllipticCurveElGamal:
            key_size = 160
        elif algorithm_name == Algorithm.Paillier:
            key_size = 1024
        elif algorithm_name == Algorithm.DamgardJurik:
            key_size = 1024
        elif algorithm_name == Algorithm.OkamotoUchiyama:
            key_size = 1024
        # n should be several hundred bits or more
        elif algorithm_name == Algorithm.GoldwasserMicali:
            key_size = 100
        # Benaloh and Naccache-Stern require to solve DLP in decryption
        # so small key is recommended
        elif algorithm_name == Algorithm.Benaloh:
            key_size = 50
        elif algorithm_name == Algorithm.NaccacheStern:
            key_size = 37
        else:
            raise ValueError(f"unimplemented algorithm - {algorithm_name}")
        return key_size

    def create_ciphertext_obj(self, ciphertext: Union[int, tuple, list]) -> Ciphertext:
        """
        Ciphertext objects have keys in addition ciphertext itself to perform
        homomorphic operations.
        Args:
            ciphertext (int or tuple or list): ciphertext content
        Returns:
            Ciphertext
        """
        return Ciphertext(algorithm_name=self.algorithm_name, keys=self.cs.keys, value=ciphertext)
