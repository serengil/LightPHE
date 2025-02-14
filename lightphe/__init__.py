# built-in dependencies
import time
import json
from typing import Optional, Union, List
import multiprocessing
from contextlib import closing

# 3rd party dependencies
from tqdm import tqdm

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.models.Ciphertext import Ciphertext
from lightphe.models.Algorithm import Algorithm
from lightphe.models.Tensor import Fraction, EncryptedTensor
from lightphe.models.EllipticCurve import EllipticCurvePoint
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
from lightphe.elliptic_curve_forms.weierstrass import Weierstrass
from lightphe.elliptic_curve_forms.edwards import TwistedEdwards
from lightphe.elliptic_curve_forms.koblitz import Koblitz


# pylint: disable=eval-used, simplifiable-if-expression, too-few-public-methods

logger = Logger(module="lightphe/__init__.py")

VERSION = "0.0.12"


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
            form (str): specifies the form of the elliptic curve.
                Options: 'weierstrass' (default), 'edwards', 'koblitz'.
                This parameter is only used if `algorithm_name` is 'EllipticCurve-ElGamal'.
            curve (str): specifies the elliptic curve to use.
                Options:
                 - e.g. ed25519, ed448 for edwards form
                 - e.g. secp256k1 for weierstrass form
                 - e.g. k-409 for koblitz form
                List of all available curves:
                    github.com/serengil/LightPHE/blob/master/lightphe/elliptic_curve_forms/README.md
                This parameter is only used if `algorithm_name` is 'EllipticCurve-ElGamal'.
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
        )

    def __build_cryptosystem(
        self,
        algorithm_name: str,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
        form: Optional[str] = None,
        curve: Optional[str] = None,
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
        Returns
            cryptosystem
        """
        # build cryptosystem
        if algorithm_name == Algorithm.RSA:
            cs = RSA(keys=keys, key_size=key_size)
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
            cs = Benaloh(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.NaccacheStern:
            cs = NaccacheStern(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.GoldwasserMicali:
            cs = GoldwasserMicali(keys=keys, key_size=key_size)
        else:
            raise ValueError(f"unimplemented algorithm - {algorithm_name}")
        return cs

    def encrypt(
        self, plaintext: Union[int, float, list]
    ) -> Union[Ciphertext, EncryptedTensor]:
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
            plaintext=phe_utils.normalize_input(
                value=plaintext, modulo=self.cs.plaintext_modulo
            )
        )
        return Ciphertext(
            algorithm_name=self.algorithm_name,
            keys=self.cs.keys,
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

    def __encrypt_tensors(self, tensor: list) -> EncryptedTensor:
        """
        Encrypt a given tensor
        Args:
            tensor (list of int or float)
        Returns
            encrypted tensor (list of encrypted tensor object)
        """
        encrypted_tensor: List[Fraction] = []

        encrypted_zero = self.cs.encrypt(plaintext=0)
        divisor_encrypted = self.cs.encrypt(plaintext=10**self.precision)
        is_positive_tensor = all(m >= 0 for m in tensor)

        num_workers = min(len(tensor), 2 * multiprocessing.cpu_count())
        logger.debug(f"encrypting tensors in {num_workers} parallel")

        with closing(multiprocessing.Pool(num_workers)) as pool:
            funclist = []

            for m in tensor:
                f = pool.apply_async(
                    encrypt_something,
                    (
                        m,
                        divisor_encrypted,
                        self.cs,
                        self.precision,
                        encrypted_zero,
                        is_positive_tensor,
                    ),
                )
                funclist.append(f)

            tic = time.time()
            encrypted_tensor = []
            for f in tqdm(
                funclist,
                desc="Encrypting tensors",
                disable=True if len(tensor) < 100 else False,
            ):
                result = f.get(timeout=10)
                encrypted_tensor.append(result)

            toc = time.time()
            logger.debug(f"encryption took {toc - tic} seconds")

            return EncryptedTensor(
                fractions=encrypted_tensor,
                cs=self.cs,
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


def encrypt_something(
    m: Union[int, float],
    divisor_encrypted,
    cs: Homomorphic,
    precision: int,
    encrypted_zero: int,
    is_positive_tensor: bool,
) -> Fraction:
    if m == 0:
        # this is very common in VGG-Face embeddings
        c = Fraction(
            dividend=encrypted_zero,
            divisor=divisor_encrypted,
            abs_dividend=encrypted_zero,
            sign=0,
        )
    elif isinstance(m, int):
        dividend_encrypted = cs.encrypt(
            plaintext=(m % cs.plaintext_modulo) * pow(10, precision)
        )
        abs_dividend_encrypted = (
            dividend_encrypted
            if is_positive_tensor
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
        dividend, _ = phe_utils.fractionize(
            value=(m % cs.plaintext_modulo),
            modulo=cs.plaintext_modulo,
            precision=precision,
        )
        abs_dividend = (
            dividend
            if is_positive_tensor
            else phe_utils.fractionize(
                value=(abs(m) % cs.plaintext_modulo),
                modulo=cs.plaintext_modulo,
                precision=precision,
            )[0]
        )
        dividend_encrypted = cs.encrypt(plaintext=dividend)
        abs_dividend_encrypted = (
            dividend_encrypted
            if is_positive_tensor
            else cs.encrypt(plaintext=abs_dividend)
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


class ECC:
    __version__ = VERSION

    def __init__(
        self, form_name: Optional[str] = None, curve_name: Optional[str] = None
    ):
        """
        Construct an Elliptic Curve over a finite field (prime or binary)
        Args:
            form_name (str): specifies the form of the elliptic curve.
                Options: 'weierstrass' (default), 'edwards', 'koblitz'.
            curve_name (str): specifies the elliptic curve to use.
                Options:
                 - e.g. ed25519, ed448 for edwards form
                 - e.g. secp256k1 for weierstrass form
                 - e.g. k-409 for koblitz form
                List of all available curves:
                    github.com/serengil/LightPHE/blob/master/lightphe/elliptic_curve_forms/README.md
        """
        if form_name is None or form_name == "weierstrass":
            self.curve = Weierstrass(curve=curve_name)
        elif form_name in "edwards":
            self.curve = TwistedEdwards(curve=curve_name)
        elif form_name in "koblitz":
            self.curve = Koblitz(curve=curve_name)
        else:
            raise ValueError(f"unimplemented curve form - {form_name}")

        # base point
        self.G = EllipticCurvePoint(self.curve.G[0], self.curve.G[1], self.curve)

        # order of the curve
        self.n = self.curve.n

        # point at infinity or neutral / identity element
        self.O = EllipticCurvePoint(self.curve.O[0], self.curve.O[1], self.curve)

        # modulo
        self.modulo = self.curve.modulo
