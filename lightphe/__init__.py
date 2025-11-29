# built-in dependencies
import time
import json
from typing import Optional, Union, List
import multiprocessing
from contextlib import closing
import traceback
import copy

# 3rd party dependencies
from tqdm import tqdm

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.models.Ciphertext import Ciphertext
from lightphe.models.Algorithm import Algorithm
from lightphe.models.Tensor import Fraction, EncryptedTensor
from lightphe.commons import phe_utils
from lightphe.commons.logger import Logger

# cryptosystems
from lightphe.cryptosystems.RSA import RSA
from lightphe.cryptosystems.ElGamal import ElGamal
from lightphe.cryptosystems.Paillier import Paillier
from lightphe.cryptosystems.DamgardJurik import DamgardJurik
from lightphe.cryptosystems.OkamotoUchiyama import OkamotoUchiyama
from lightphe.cryptosystems.Benaloh import Benaloh
from lightphe.cryptosystems.NaccacheStern import NaccacheStern
from lightphe.cryptosystems.GoldwasserMicali import GoldwasserMicali
from lightphe.cryptosystems.EllipticCurveElGamal import EllipticCurveElGamal


# pylint: disable=eval-used, simplifiable-if-expression, too-few-public-methods

logger = Logger(module="lightphe/__init__.py")

VERSION = "0.0.19"


class LightPHE:
    __version__ = VERSION

    def __init__(
        self,
        algorithm_name: str,
        keys: Optional[dict] = None,
        key_file: Optional[str] = None,
        key_size: Optional[int] = None,
        precision: int = 5,
        form: Optional[str] = None,
        curve: Optional[str] = None,
        plaintext_limit: Optional[int] = None,
        max_tries: int = 10000,
    ):
        """
        Build LightPHE class
        Args:
            algorithm_name (str): RSA | ElGamal | Exponential-ElGamal | EllipticCurve-ElGamal
                | Paillier | Damgard-Jurik | Okamoto-Uchiyama | Benaloh | Naccache-Stern
                | Goldwasser-Micali
            keys (dict): optional private-public key pair
            key_file (str): if keys were exported already, you can load them into cryptosystem
            key_size (int): key size in bits
            precision (int): precision for homomorphic operations on tensors
            form (str): specifies the form of the elliptic curve.
                Options: 'weierstrass' (default), 'edwards', 'koblitz'.
                This parameter is only used if `algorithm_name` is 'EllipticCurve-ElGamal'.
            curve (str): specifies the elliptic curve to use.
                Options:
                 - e.g. ed25519, ed448 for edwards form
                 - e.g. secp256k1 for weierstrass form
                 - e.g. k-409 for koblitz form
                List of all available curves:
                    https://github.com/serengil/LightECC?tab=readme-ov-file#supported-curves
                This parameter is only used if `algorithm_name` is 'EllipticCurve-ElGamal'.
            plaintext_limit (int, optional): Upper bound for plaintext values.
                This parameter is only used if `algorithm_name` is 'Benaloh'.
            max_tries (int): maximum attempts to generate keys. Default is 10000.
                RSA, Benaloh, Naccache-Stern and Goldwasser-Micali algorithms
                need multiple attempts to generate valid keys. Will be discarded
                for other algorithms.
        """
        self.algorithm_name = algorithm_name
        self.precision = precision
        self.form = form
        self.curve = curve

        if key_file is not None:
            keys = self.restore_keys(target_file=key_file)

        self.cs: Homomorphic = self.__build_cryptosystem(
            algorithm_name=algorithm_name,
            keys=keys,
            key_size=key_size,
            form=form,
            curve=curve,
            plaintext_limit=plaintext_limit,
            max_tries=max_tries,
        )

    def __build_cryptosystem(
        self,
        algorithm_name: str = "Paillier",
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
        form: Optional[str] = None,
        curve: Optional[str] = None,
        plaintext_limit: Optional[int] = None,
        max_tries: int = 10000,
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
                | Goldwasser-Micali | Edwards-ElGamal
                Default is Paillier.
            keys (dict): optional private-public key pair
            key_file (str): if keys are exported, you can load them into cryptosystem
            key_size (int): key size in bits
            form (str): specifies the form of the elliptic curve.
                Options: 'weierstrass' (default), 'edwards'.
                This parameter is only used if `algorithm_name` is 'EllipticCurve-ElGamal'.
            curve (str): specifies the elliptic curve to use.
                Options:
                 - ed25519, ed448 for edwards form
                 - secp256k1 for weierstrass form
                This parameter is only used if `algorithm_name` is 'EllipticCurve-ElGamal'.
            plaintext_limit (int, optional): Upper bound for plaintext values.
                This parameter is only used if `algorithm_name` is 'Benaloh'.
            max_tries (int): maximum attempts to generate keys. Default is 10000.
                RSA, Benaloh, Naccache-Stern and Goldwasser-Micali algorithms
                need multiple attempts to generate valid keys. Will be discarded
                for other algorithms.
        Returns
            cryptosystem
        """
        # build cryptosystem
        if algorithm_name == Algorithm.RSA:
            cs = RSA(keys=keys, key_size=key_size, max_tries=max_tries)
        elif algorithm_name == Algorithm.ElGamal:
            cs = ElGamal(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.ExponentialElGamal:
            cs = ElGamal(keys=keys, key_size=key_size, exponential=True)
        elif algorithm_name == Algorithm.EllipticCurveElGamal:
            cs = EllipticCurveElGamal(
                keys=keys, key_size=key_size, form=form, curve=curve
            )
        elif algorithm_name == Algorithm.Paillier:
            cs = Paillier(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.DamgardJurik:
            cs = DamgardJurik(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.OkamotoUchiyama:
            cs = OkamotoUchiyama(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.Benaloh:
            cs = Benaloh(
                keys=keys,
                key_size=key_size,
                plaintext_limit=plaintext_limit,
                max_tries=max_tries,
            )
        elif algorithm_name == Algorithm.NaccacheStern:
            cs = NaccacheStern(keys=keys, key_size=key_size, max_tries=max_tries)
        elif algorithm_name == Algorithm.GoldwasserMicali:
            cs = GoldwasserMicali(keys=keys, key_size=key_size, max_tries=max_tries)
        else:
            raise ValueError(f"unimplemented algorithm - {algorithm_name}")
        return cs

    def encrypt(
        self, plaintext: Union[int, float, list], silent: bool = False
    ) -> Union[Ciphertext, EncryptedTensor]:
        """
        Encrypt a plaintext with a built cryptosystem
        Args:
            plaintext (int, float or tensor): message
            silent (bool): set this to True if you do not want to see progress bar
        Returns
            ciphertext (from lightphe.models.Ciphertext import Ciphertext): encrypted message
        """
        if self.cs.keys.get("public_key") is None:
            raise ValueError("You must have public key to perform encryption")

        if isinstance(plaintext, list):
            # then encrypt tensors
            return self.__encrypt_tensors(tensor=plaintext, silent=silent)

        ciphertext = self.cs.encrypt(
            plaintext=phe_utils.normalize_input(
                value=plaintext, modulo=self.cs.plaintext_modulo
            )
        )

        public_keys = self.cs.keys.copy()
        if public_keys.get("private_key") is not None:
            del public_keys["private_key"]

        return Ciphertext(
            algorithm_name=self.algorithm_name,
            keys=public_keys,
            value=ciphertext,
            form=self.form,
            curve=self.curve,
        )

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

    def __encrypt_tensors(self, tensor: list, silent: bool = False) -> EncryptedTensor:
        """
        Encrypt a given tensor
        Args:
            tensor (list of int or float)
            silent (bool): set this to True if you do not want to see progress bar
        Returns
            encrypted tensor (list of encrypted tensor object)
        """
        encrypted_tensor: List[Fraction] = []

        encrypted_zero = self.cs.encrypt(plaintext=0)
        divisor_encrypted = self.cs.encrypt(plaintext=10**self.precision)

        num_workers = min(len(tensor), 2 * multiprocessing.cpu_count())
        logger.debug(f"encrypting tensors in {num_workers} parallel")

        with closing(multiprocessing.Pool(num_workers)) as pool:
            funclist = []

            for m in tensor:
                f = pool.apply_async(
                    encrypt_float,
                    (
                        m,
                        divisor_encrypted,
                        self.cs,
                        self.precision,
                        encrypted_zero,
                    ),
                )
                funclist.append(f)

            tic = time.time()
            encrypted_tensor = []
            for f in tqdm(
                funclist,
                desc="Encrypting tensors",
                disable=silent,
            ):
                result = f.get(timeout=10)
                encrypted_tensor.append(result)

            toc = time.time()
            logger.debug(f"encryption took {toc - tic} seconds")

            public_cs = copy.deepcopy(self.cs)
            if public_cs.keys.get("private_key") is not None:
                del public_cs.keys["private_key"]

            return EncryptedTensor(
                fractions=encrypted_tensor,
                cs=public_cs,
                precision=self.precision,
            )

    def __decrypt_tensors(
        self, encrypted_tensor: EncryptedTensor
    ) -> Union[List[int], List[float]]:
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

            # TODO: do I really need encrypted divisor? cannot I store current_precision
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
        if self.cs.keys.get("public_key") is None:
            raise ValueError("You must have public key to perform decryption")

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

    def create_ciphertext_obj(self, ciphertext: Union[int, tuple, list]) -> Ciphertext:
        """
        Ciphertext objects have keys in addition ciphertext itself to perform
        homomorphic operations.
        Args:
            ciphertext (int or tuple or list): ciphertext content
        Returns:
            Ciphertext
        """
        return Ciphertext(
            algorithm_name=self.algorithm_name, keys=self.cs.keys, value=ciphertext
        )


def encrypt_float(
    m: Union[int, float],
    divisor_encrypted: int,
    cs: Homomorphic,
    precision: int,
    encrypted_zero: int,
) -> Fraction:
    """
    Encrypt a float value
    Args:
        m (int or float): message to encrypt
        divisor_encrypted (int): pre-calculated encrypted divisor
        cs (Homomorphic): cryptosystem itself
        precision (int): define how many digits after dot
        encrypted_zero (int): pre-calculated encrypted value of 0
    Returns:
        result (Fraction): encrypted float value
    """
    try:
        if m == 0:
            # this is very common in VGG-Face embeddings
            c = Fraction(
                dividend=encrypted_zero,
                divisor=divisor_encrypted,
                abs_dividend=encrypted_zero,
                sign=1,
            )
        elif isinstance(m, int):
            dividend_encrypted = cs.encrypt(
                plaintext=(m % cs.plaintext_modulo) * pow(10, precision)
            )
            abs_dividend_encrypted = (
                dividend_encrypted
                if m > 0
                else cs.encrypt(
                    plaintext=(abs(m) % cs.plaintext_modulo) * pow(10, precision)
                )
            )
            # divisor_encrypted = self.cs.encrypt(plaintext=pow(10, self.precision))
            c = Fraction(
                dividend=dividend_encrypted,
                divisor=divisor_encrypted,
                abs_dividend=abs_dividend_encrypted,
                sign=1 if m >= 0 else -1,
            )
        elif isinstance(m, float):
            # got `int too large to convert float` while m mod plaintext modulo
            # when security level is set to 128
            dividend, _ = phe_utils.fractionize(
                value=(m % cs.plaintext_modulo if m > cs.plaintext_modulo else m),
                modulo=cs.plaintext_modulo,
                precision=precision,
            )
            abs_dividend = (
                dividend
                if m > 0
                else phe_utils.fractionize(
                    value=(
                        abs(m) % cs.plaintext_modulo
                        if abs(m) > cs.plaintext_modulo
                        else abs(m)
                    ),
                    modulo=cs.plaintext_modulo,
                    precision=precision,
                )[0]
            )
            dividend_encrypted = cs.encrypt(plaintext=dividend)
            abs_dividend_encrypted = (
                dividend_encrypted if m > 0 else cs.encrypt(plaintext=abs_dividend)
            )
            # divisor_encrypted = self.cs.encrypt(plaintext=_divisor)
            c = Fraction(
                dividend=dividend_encrypted,
                divisor=divisor_encrypted,
                abs_dividend=abs_dividend_encrypted,
                sign=1 if m >= 0 else -1,
            )
        else:
            raise ValueError(f"unimplemented type - {type(m)}")

        return c
    except Exception as err:
        logger.error(f"Exception while running encrypt_float: {str(err)}")
        logger.error(traceback.format_exc())
        raise err
