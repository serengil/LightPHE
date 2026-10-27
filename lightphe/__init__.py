# built-in dependencies
import time
import json
from typing import Any, Optional, Union, List, Tuple, Callable
import multiprocessing
from contextlib import closing
import traceback
import copy

# 3rd party dependencies
from tqdm import tqdm
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.models.Ciphertext import Ciphertext
from lightphe.models.Algorithm import Algorithm
from lightphe.models.Tensor import Fraction, EncryptedTensor
from lightphe.models.CatalanoFiore import (
    CatalanoFiore,
    CatalanoFioreCiphertext,
    BOOST_NAME as CATALANO_FIORE,
)
from lightphe.commons import phe_utils
from lightphe.commons import threshold as threshold_utils
from lightphe.commons import zkp
from lightphe.commons import nearest_neighbors
from lightphe.commons import secure_aggregation
from lightphe.commons import classifiers
from lightphe.commons.key_validator import validate_keys
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
from lightphe.cryptosystems.SanderYoungYung import SanderYoungYung
from lightphe.cryptosystems.BonehGohNissim import BonehGohNissim
from lightphe.cryptosystems.JoyeLibert import JoyeLibert, FLOAT_NOT_SUPPORTED_MSG
from lightphe.cryptosystems.CastagnosLaguillaumie import CastagnosLaguillaumie
from lightphe.cryptosystems.IshaiPaskin import IshaiPaskin
from lightphe.cryptosystems.DamgardGeislerKroigaard import DamgardGeislerKroigaard
from lightphe.cryptosystems.BressonCatalanoPointcheval import BressonCatalanoPointcheval
from lightphe.cryptosystems.CamenischShoup import CamenischShoup
from lightphe.cryptosystems.EllipticCurvePaillier import EllipticCurvePaillier
from lightphe.cryptosystems.Regev import (
    Regev,
    FLOAT_NOT_SUPPORTED_MSG as REGEV_FLOAT_NOT_SUPPORTED_MSG,
)
from lightphe.cryptosystems.BrakerskiVaikuntanathan import (
    BrakerskiVaikuntanathan,
    FLOAT_NOT_SUPPORTED_MSG as BV_FLOAT_NOT_SUPPORTED_MSG,
)
from lightphe.cryptosystems.FreemanBonehGohNissim import (
    FreemanBonehGohNissim,
    FLOAT_NOT_SUPPORTED_MSG as FBGN_FLOAT_NOT_SUPPORTED_MSG,
)
from lightphe.cryptosystems.GentryHaleviVaikuntanathan import (
    GentryHaleviVaikuntanathan,
    FLOAT_NOT_SUPPORTED_MSG as GHV_FLOAT_NOT_SUPPORTED_MSG,
)
from lightphe.cryptosystems.LyubashevskyPeikertRegev import (
    LyubashevskyPeikertRegev,
    FLOAT_NOT_SUPPORTED_MSG as LPR_FLOAT_NOT_SUPPORTED_MSG,
)
from lightphe.cryptosystems.MLKEM import (
    MLKEM,
    FLOAT_NOT_SUPPORTED_MSG as MLKEM_FLOAT_NOT_SUPPORTED_MSG,
)
from lightphe.cryptosystems.GentrySahaiWaters import (
    GentrySahaiWaters,
    FLOAT_NOT_SUPPORTED_MSG as GSW_FLOAT_NOT_SUPPORTED_MSG,
)

# pylint: disable=eval-used, simplifiable-if-expression, too-few-public-methods, too-many-public-methods

logger = Logger(module="lightphe/__init__.py")

VERSION = "0.0.27"


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
        boost: Optional[str] = None,
        prime_order: bool = False,
        safe_primes: bool = False,
    ):
        """
        Build LightPHE class
        Args:
            algorithm_name (str): RSA | ElGamal | Exponential-ElGamal | EllipticCurve-ElGamal
                | Paillier | Damgard-Jurik | Okamoto-Uchiyama | Benaloh | Naccache-Stern
                | Goldwasser-Micali | Sander-Young-Yung | Boneh-Goh-Nissim
                | Joye-Libert | Castagnos-Laguillaumie | Ishai-Paskin
                | Damgard-Geisler-Kroigaard | Bresson-Catalano-Pointcheval
                | Camenisch-Shoup | EllipticCurve-Paillier | Regev
                | Brakerski-Vaikuntanathan | Freeman-Boneh-Goh-Nissim
                | Gentry-Halevi-Vaikuntanathan | Lyubashevsky-Peikert-Regev | ML-KEM
                | Gentry-Sahai-Waters
            keys (dict): optional private-public key pair
            key_file (str): if keys were exported already, you can load them into cryptosystem
            key_size (int): key size in bits. For Regev, it is the lattice dimension.
                For Brakerski-Vaikuntanathan, Lyubashevsky-Peikert-Regev and
                Gentry-Sahai-Waters, it is the ring degree. For ML-KEM, it is the parameter set: 512, 768 or 1024.
                For Freeman-Boneh-Goh-Nissim, it is the bit length of the field size.
                For Gentry-Halevi-Vaikuntanathan, it is the lattice dimension in [2, 8].
            precision (int): precision for homomorphic operations on tensors
            form (str): specifies the form of the elliptic curve.
                Options: 'weierstrass' (default), 'edwards', 'koblitz'.
                This parameter is only used if `algorithm_name` is 'EllipticCurve-ElGamal'
                or 'Camenisch-Shoup'. Camenisch-Shoup uses it for verifiable encryption.
            curve (str): specifies the elliptic curve to use.
                Options:
                 - e.g. ed25519, ed448 for edwards form
                 - e.g. secp256k1 for weierstrass form
                 - e.g. k-409 for koblitz form
                List of all available curves:
                    https://github.com/serengil/LightECC?tab=readme-ov-file#supported-curves
                This parameter is only used if `algorithm_name` is 'EllipticCurve-ElGamal'
                or 'Camenisch-Shoup'. Camenisch-Shoup uses it for verifiable encryption.
            plaintext_limit (int, optional): Upper bound for plaintext values.
                This parameter is only used if `algorithm_name` is 'Benaloh', 'Regev',
                'Brakerski-Vaikuntanathan', 'Freeman-Boneh-Goh-Nissim',
                'Gentry-Halevi-Vaikuntanathan' or 'Lyubashevsky-Peikert-Regev'.
            max_tries (int): maximum attempts to generate keys. Default is 10000.
                RSA, Benaloh, Naccache-Stern, Goldwasser-Micali, Boneh-Goh-Nissim,
                Joye-Libert, Castagnos-Laguillaumie, Damgard-Geisler-Kroigaard,
                Bresson-Catalano-Pointcheval and Camenisch-Shoup algorithms
                need multiple attempts to generate valid keys. Will be discarded
                for other algorithms.
            boost (str): upgrades the algorithm with a transform. Default is None.
                Options:
                 - Catalano-Fiore: lets ciphertexts of an additively homomorphic algorithm
                    be multiplied once. Then, encrypt returns ciphertexts supporting one
                    multiplication, and only integers are supported.
                    Supported for Paillier, Damgard-Jurik, Bresson-Catalano-Pointcheval,
                    Camenisch-Shoup, EllipticCurve-Paillier, Joye-Libert,
                    Castagnos-Laguillaumie, Naccache-Stern, Benaloh and
                    Damgard-Geisler-Kroigaard.
            prime_order (bool): picks the generator of a known prime order while
                generating keys. Default is False. Threshold decryption requires this.
                This parameter is only used if `algorithm_name` is 'ElGamal' or
                'Exponential-ElGamal'.
            safe_primes (bool): generates the modulus as a product of two safe primes.
                Default is False. Proofs of partial decryption in threshold decryption
                require this. This parameter is only used if `algorithm_name` is
                'Paillier' or 'Damgard-Jurik'.
        """
        self.algorithm_name = algorithm_name
        self.precision = precision
        self.form = form
        self.curve = curve

        if key_file is not None:
            keys = self.restore_keys(target_file=key_file)

        if (
            safe_primes is True
            and keys is None
            and algorithm_name in [Algorithm.Paillier, Algorithm.DamgardJurik]
        ):
            keys = threshold_utils.generate_safe_paillier_keys(
                key_size=key_size or 1024,
                max_tries=max_tries,
                s=2 if algorithm_name == Algorithm.DamgardJurik else None,
            )

        if keys is not None:
            validate_keys(algorithm_name=algorithm_name, keys=keys)

        self.cs: Homomorphic = self.__build_cryptosystem(
            algorithm_name=algorithm_name,
            keys=keys,
            key_size=key_size,
            form=form,
            curve=curve,
            plaintext_limit=plaintext_limit,
            max_tries=max_tries,
            prime_order=prime_order,
        )

        # public-key-only cryptosystem shared by ciphertexts, built on first use
        self.__public_cs: Optional[Homomorphic] = None

        # Catalano-Fiore transform wraps a copy of this instance without the transform
        self.__catalano_fiore: Optional[CatalanoFiore] = None
        if boost is not None:
            if boost != CATALANO_FIORE:
                raise ValueError(
                    f"Unknown boost {boost}. Options are: {CATALANO_FIORE}"
                )
            self.__catalano_fiore = CatalanoFiore(copy.copy(self))

    def __public_ciphertext(self, value: Union[int, tuple, list]) -> Ciphertext:
        """
        Wrap a ciphertext value into a Ciphertext carrying public keys only
        Args:
            value (int or tuple or list): ciphertext content
        Returns:
            ciphertext (Ciphertext)
        """
        if self.__public_cs is None:
            public_keys = self.cs.keys.copy()
            if public_keys.get("private_key") is not None:
                del public_keys["private_key"]
            ciphertext = Ciphertext(
                algorithm_name=self.algorithm_name,
                keys=public_keys,
                value=value,
                form=self.form,
                curve=self.curve,
            )
            self.__public_cs = ciphertext.cs
            return ciphertext

        return Ciphertext(
            algorithm_name=self.algorithm_name,
            keys=self.__public_cs.keys,
            value=value,
            form=self.form,
            curve=self.curve,
            cs=self.__public_cs,
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
        prime_order: bool = False,
    ) -> Union[
        RSA,
        ElGamal,
        Paillier,
        DamgardJurik,
        OkamotoUchiyama,
        Benaloh,
        NaccacheStern,
        EllipticCurveElGamal,
        SanderYoungYung,
        BonehGohNissim,
        JoyeLibert,
        CastagnosLaguillaumie,
        IshaiPaskin,
        DamgardGeislerKroigaard,
        BressonCatalanoPointcheval,
        CamenischShoup,
        EllipticCurvePaillier,
        Regev,
        BrakerskiVaikuntanathan,
        FreemanBonehGohNissim,
        GentryHaleviVaikuntanathan,
        LyubashevskyPeikertRegev,
        MLKEM,
        GentrySahaiWaters,
    ]:
        """
        Build a cryptosystem among partially homomorphic algorithms
        Args:
            algorithm_name (str): RSA | ElGamal | Exponential-ElGamal | EllipticCurve-ElGamal
                | Paillier | Damgard-Jurik | Okamoto-Uchiyama | Benaloh | Naccache-Stern
                | Goldwasser-Micali | Edwards-ElGamal | Sander-Young-Yung | Boneh-Goh-Nissim
                | Joye-Libert | Castagnos-Laguillaumie | Ishai-Paskin
                | Damgard-Geisler-Kroigaard | Bresson-Catalano-Pointcheval
                | Camenisch-Shoup | EllipticCurve-Paillier | Regev
                | Brakerski-Vaikuntanathan | Freeman-Boneh-Goh-Nissim
                | Gentry-Halevi-Vaikuntanathan | Lyubashevsky-Peikert-Regev | ML-KEM
                | Gentry-Sahai-Waters
                Default is Paillier.
            keys (dict): optional private-public key pair
            key_file (str): if keys are exported, you can load them into cryptosystem
            key_size (int): key size in bits. For Regev, it is the lattice dimension.
                For Brakerski-Vaikuntanathan, Lyubashevsky-Peikert-Regev and
                Gentry-Sahai-Waters, it is the ring degree. For ML-KEM, it is the parameter set: 512, 768 or 1024.
                For Freeman-Boneh-Goh-Nissim, it is the bit length of the field size.
                For Gentry-Halevi-Vaikuntanathan, it is the lattice dimension in [2, 8].
            form (str): specifies the form of the elliptic curve.
                Options: 'weierstrass' (default), 'edwards'.
                This parameter is only used if `algorithm_name` is 'EllipticCurve-ElGamal'
                or 'Camenisch-Shoup'. Camenisch-Shoup uses it for verifiable encryption.
            curve (str): specifies the elliptic curve to use.
                Options:
                 - ed25519, ed448 for edwards form
                 - secp256k1 for weierstrass form
                This parameter is only used if `algorithm_name` is 'EllipticCurve-ElGamal'
                or 'Camenisch-Shoup'. Camenisch-Shoup uses it for verifiable encryption.
            plaintext_limit (int, optional): Upper bound for plaintext values.
                This parameter is only used if `algorithm_name` is 'Benaloh', 'Regev',
                'Brakerski-Vaikuntanathan', 'Freeman-Boneh-Goh-Nissim',
                'Gentry-Halevi-Vaikuntanathan' or 'Lyubashevsky-Peikert-Regev'.
            max_tries (int): maximum attempts to generate keys. Default is 10000.
                RSA, Benaloh, Naccache-Stern, Goldwasser-Micali, Boneh-Goh-Nissim,
                Joye-Libert, Castagnos-Laguillaumie, Damgard-Geisler-Kroigaard,
                Bresson-Catalano-Pointcheval and Camenisch-Shoup algorithms
                need multiple attempts to generate valid keys. Will be discarded
                for other algorithms.
            prime_order (bool): picks the generator of a known prime order while
                generating keys of ElGamal or Exponential-ElGamal.
        Returns
            cryptosystem
        """
        # build cryptosystem
        if algorithm_name == Algorithm.RSA:
            cs = RSA(keys=keys, key_size=key_size, max_tries=max_tries)
        elif algorithm_name == Algorithm.ElGamal:
            cs = ElGamal(keys=keys, key_size=key_size, prime_order=prime_order)
        elif algorithm_name == Algorithm.ExponentialElGamal:
            cs = ElGamal(
                keys=keys, key_size=key_size, exponential=True, prime_order=prime_order
            )
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
        elif algorithm_name == Algorithm.SanderYoungYung:
            cs = SanderYoungYung(
                keys=keys, key_size=key_size, plaintext_limit=plaintext_limit
            )
        elif algorithm_name == Algorithm.BonehGohNissim:
            cs = BonehGohNissim(keys=keys, key_size=key_size, max_tries=max_tries)
        elif algorithm_name == Algorithm.JoyeLibert:
            cs = JoyeLibert(keys=keys, key_size=key_size, max_tries=max_tries)
        elif algorithm_name == Algorithm.CastagnosLaguillaumie:
            cs = CastagnosLaguillaumie(
                keys=keys, key_size=key_size, max_tries=max_tries
            )
        elif algorithm_name == Algorithm.IshaiPaskin:
            cs = IshaiPaskin(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.DamgardGeislerKroigaard:
            cs = DamgardGeislerKroigaard(
                keys=keys, key_size=key_size, max_tries=max_tries
            )
        elif algorithm_name == Algorithm.BressonCatalanoPointcheval:
            cs = BressonCatalanoPointcheval(
                keys=keys, key_size=key_size, max_tries=max_tries
            )
        elif algorithm_name == Algorithm.CamenischShoup:
            cs = CamenischShoup(
                keys=keys,
                key_size=key_size,
                max_tries=max_tries,
                form=form,
                curve=curve,
            )
        elif algorithm_name == Algorithm.EllipticCurvePaillier:
            cs = EllipticCurvePaillier(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.Regev:
            cs = Regev(keys=keys, key_size=key_size, plaintext_limit=plaintext_limit)
        elif algorithm_name == Algorithm.BrakerskiVaikuntanathan:
            cs = BrakerskiVaikuntanathan(
                keys=keys, key_size=key_size, plaintext_limit=plaintext_limit
            )
        elif algorithm_name == Algorithm.FreemanBonehGohNissim:
            cs = FreemanBonehGohNissim(
                keys=keys, key_size=key_size, plaintext_limit=plaintext_limit
            )
        elif algorithm_name == Algorithm.GentryHaleviVaikuntanathan:
            cs = GentryHaleviVaikuntanathan(
                keys=keys, key_size=key_size, plaintext_limit=plaintext_limit
            )
        elif algorithm_name == Algorithm.LyubashevskyPeikertRegev:
            cs = LyubashevskyPeikertRegev(
                keys=keys, key_size=key_size, plaintext_limit=plaintext_limit
            )
        elif algorithm_name == Algorithm.MLKEM:
            cs = MLKEM(keys=keys, key_size=key_size)
        elif algorithm_name == Algorithm.GentrySahaiWaters:
            cs = GentrySahaiWaters(keys=keys, key_size=key_size)
        else:
            raise ValueError(f"unimplemented algorithm - {algorithm_name}")
        return cs

    def encrypt(
        self, plaintext: Union[int, float, list], silent: bool = False
    ) -> Union[Ciphertext, EncryptedTensor, CatalanoFioreCiphertext]:
        """
        Encrypt a plaintext with a built cryptosystem
        Args:
            plaintext (int, float or tensor): message
            silent (bool): set this to True if you do not want to see progress bar
        Returns
            ciphertext (from lightphe.models.Ciphertext import Ciphertext): encrypted message.
                it supports one multiplication if Catalano-Fiore boost is set.
        """
        if self.cs.keys.get("public_key") is None:
            raise ValueError("You must have public key to perform encryption")

        if self.__catalano_fiore is not None:
            return self.__catalano_fiore.encrypt(plaintext=plaintext)

        if self.algorithm_name == Algorithm.Regev and isinstance(
            plaintext, (list, float)
        ):
            raise ValueError(REGEV_FLOAT_NOT_SUPPORTED_MSG)

        if self.algorithm_name == Algorithm.BrakerskiVaikuntanathan and isinstance(
            plaintext, (list, float)
        ):
            raise ValueError(BV_FLOAT_NOT_SUPPORTED_MSG)

        if self.algorithm_name == Algorithm.FreemanBonehGohNissim and isinstance(
            plaintext, (list, float)
        ):
            raise ValueError(FBGN_FLOAT_NOT_SUPPORTED_MSG)

        if self.algorithm_name == Algorithm.GentryHaleviVaikuntanathan and isinstance(
            plaintext, (list, float)
        ):
            raise ValueError(GHV_FLOAT_NOT_SUPPORTED_MSG)

        if self.algorithm_name == Algorithm.LyubashevskyPeikertRegev and isinstance(
            plaintext, (list, float)
        ):
            raise ValueError(LPR_FLOAT_NOT_SUPPORTED_MSG)

        if self.algorithm_name == Algorithm.MLKEM and isinstance(plaintext, (list, float)):
            raise ValueError(MLKEM_FLOAT_NOT_SUPPORTED_MSG)

        if self.algorithm_name == Algorithm.GentrySahaiWaters and plaintext not in [0, 1]:
            raise ValueError(GSW_FLOAT_NOT_SUPPORTED_MSG)

        if isinstance(plaintext, list):
            # then encrypt tensors
            return self.__encrypt_tensors(tensor=plaintext, silent=silent)

        if isinstance(plaintext, float) and self.algorithm_name == Algorithm.JoyeLibert:
            raise ValueError(FLOAT_NOT_SUPPORTED_MSG)

        ciphertext = self.cs.encrypt(
            plaintext=phe_utils.normalize_input(
                value=plaintext, modulo=self.cs.plaintext_modulo
            )
        )

        return self.__public_ciphertext(value=ciphertext)

    def decrypt(
        self, ciphertext: Union[Ciphertext, EncryptedTensor, CatalanoFioreCiphertext]
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

        if isinstance(ciphertext, CatalanoFioreCiphertext):
            catalano_fiore = self.__catalano_fiore or CatalanoFiore(copy.copy(self))
            return catalano_fiore.decrypt(ciphertext=ciphertext)

        if isinstance(ciphertext, EncryptedTensor):
            # then this is encrypted tensor
            return self.__decrypt_tensors(encrypted_tensor=ciphertext)

        return self.cs.decrypt(ciphertext=ciphertext.value)

    def decrypt_with_master_key(
        self, ciphertext: Union[Ciphertext, EncryptedTensor]
    ) -> Union[int, List[int], List[float]]:
        """
        Decrypt a ciphertext with the master key instead of the private key of its owner.
            The master key can decrypt ciphertexts of all users sharing it.
            Only supported by Bresson-Catalano-Pointcheval.
        Args:
            ciphertext (Ciphertext or EncryptedTensor): encrypted message of any user
        Returns:
            plaintext (int or tensor): restored message
        """
        self.__require_key("private_key", "perform decryption")
        self.__require_key("public_key", "perform decryption")

        if isinstance(ciphertext, EncryptedTensor):
            public_key = ciphertext.cs.keys["public_key"]
            return self.__decrypt_tensors(
                encrypted_tensor=ciphertext,
                decrypt=lambda c: self.cs.decrypt_with_master_key(
                    ciphertext=c, public_key=public_key
                ),
            )

        return self.cs.decrypt_with_master_key(
            ciphertext=ciphertext.value,
            public_key=(ciphertext.keys or {}).get("public_key"),
        )

    def generate_user_keys(self) -> dict:
        """
        Generate a key pair for a new user of a master key. Public key of the authority
            holding the master key is enough to generate it. The master key can decrypt
            ciphertexts encrypted for the new user, but the new user cannot decrypt
            ciphertexts of others. Only supported by Bresson-Catalano-Pointcheval.
        Returns:
            keys (dict): private - public key pair of the new user
        """
        self.__require_key("public_key", "generate user keys")
        return self.cs.generate_user_keys()

    def encrypt_verifiably(self, secret: int, label: str = "") -> dict:
        """
        Encrypt the discrete logarithm of an elliptic curve point, e.g. a private key,
            for the owner of this cryptosystem and prove that the ciphertext contains it.
            Runs on prover side, e.g. Alice escrowing her wallet key to a trusted third
            party. Only the prover can call this, because it needs the secret itself.
            Public key of the trusted third party is enough, the private key is not needed.
            Output is sent to the verifier, who checks it with verify_encryption.
            Only supported by Camenisch-Shoup.
        Args:
            secret (int): discrete logarithm of the public point, i.e. public point = G * secret
            label (str): public data bound to the ciphertext, e.g. decryption conditions.
                The ciphertext cannot be decrypted with a different label.
        Returns:
            verifiable ciphertext (dict): ciphertext, commitment and proof
        """
        self.__require_key("public_key", "perform encryption")
        return self.cs.encrypt_verifiably(secret=secret, label=label)

    def verify_encryption(
        self,
        verifiable_ciphertext: dict,
        public_point: Union[tuple, EllipticCurvePoint],
        label: str = "",
    ) -> bool:
        """
        Verify that a verifiable ciphertext contains the discrete logarithm of a public
            point without decrypting it. Runs on verifier side, e.g. a bank that knows
            Alice's public key only. The verifier cannot trust the prover's word, because
            the prover could encrypt 0 or an unrelated key instead. This checks the proof
            against the public point and the label that the verifier already knows, so it
            confirms the escrow is real without learning the secret. Public key of the
            trusted third party is enough, the private key is not needed.
            Only supported by Camenisch-Shoup.
        Args:
            verifiable_ciphertext (dict): created by encrypt_verifiably
            public_point (tuple or EllipticCurvePoint): public point known by the verifier
            label (str): label that the ciphertext is expected to be bound to
        Returns:
            is valid (bool): True if the ciphertext contains the secret of the public point
        """
        self.__require_key("public_key", "verify encryption")
        return self.cs.verify_encryption(
            verifiable_ciphertext=verifiable_ciphertext,
            public_point=public_point,
            label=label,
        )

    def decrypt_verifiable_ciphertext(
        self, verifiable_ciphertext: dict, label: str = ""
    ) -> int:
        """
        Restore the secret from a verifiable ciphertext. Runs on the side of the private
            key owner, e.g. a trusted third party, when the conditions in the label are met.
            This is the only step requiring the private key, and the only way to restore
            the secret. It does not check the proof, as verify_encryption does that.
            Only supported by Camenisch-Shoup.
        Args:
            verifiable_ciphertext (dict): created by encrypt_verifiably
            label (str): label used in encryption
        Returns:
            secret (int): discrete logarithm of the public point
        """
        self.__require_key("private_key", "perform decryption")
        return self.cs.decrypt_verifiable_ciphertext(
            verifiable_ciphertext=verifiable_ciphertext, label=label
        )

    def generate_threshold_keys(self, threshold: int, parties: int) -> List[dict]:
        """
        Split the private key into shares for threshold decryption. Any threshold many
            shareholders can decrypt a ciphertext together, but fewer shareholders cannot.
            Runs on dealer side. Threshold parameters are added into the public key, and
            the private key is dropped from this cryptosystem afterwards, so export the
            public key again. Supported by ElGamal, Exponential-ElGamal,
            EllipticCurve-ElGamal, Paillier and Damgard-Jurik. ElGamal and
            Exponential-ElGamal keys must be generated with prime_order=True.
        Args:
            threshold (int): minimum number of shareholders required to decrypt
            parties (int): total number of shareholders
        Returns:
            keys of shareholders (list of dict): public key and share of each shareholder.
                Each item must be sent to its own shareholder secretly.
        """
        self.__require_key("private_key", "generate threshold keys")
        self.__require_key("public_key", "generate threshold keys")
        threshold_utils.validate_threshold(threshold=threshold, parties=parties)

        share_keys = self.cs.generate_threshold_keys(threshold=threshold, parties=parties)

        # dealer forgets the private key, and public key now has threshold parameters
        del self.cs.keys["private_key"]
        self.__public_cs = None

        return share_keys

    def partial_decrypt(
        self, ciphertext: Union[Ciphertext, EncryptedTensor], prove: bool = False
    ) -> Union[dict, List[dict]]:
        """
        Decrypt a ciphertext partially with the share of a shareholder. Partial
            decryption reveals nothing about the plaintext alone. Runs on shareholder side.
        Args:
            ciphertext (Ciphertext or EncryptedTensor): encrypted message
            prove (bool): set this to True to attach a zero-knowledge proof that the
                partial decryption is computed with the share of this shareholder.
                Default is False. Supported by ElGamal, Exponential-ElGamal,
                EllipticCurve-ElGamal, and Paillier and Damgard-Jurik with keys
                generated with safe_primes=True.
        Returns:
            partial decryption (dict or list of dict): to be sent to the combiner
        """
        if self.cs.keys.get("threshold_key") is None:
            raise ValueError("You must have threshold key to perform partial decryption")

        if isinstance(ciphertext, CatalanoFioreCiphertext):
            raise ValueError(
                "Ciphertexts supporting multiplication do not support threshold decryption"
            )

        if isinstance(ciphertext, EncryptedTensor):
            return [
                {
                    "abs_dividend": self.cs.partial_decrypt(
                        ciphertext=c.abs_dividend, prove=prove
                    ),
                    "divisor": self.cs.partial_decrypt(ciphertext=c.divisor, prove=prove),
                }
                for c in ciphertext.fractions
            ]

        return self.cs.partial_decrypt(ciphertext=ciphertext.value, prove=prove)

    def combine_partial_decryptions(
        self,
        ciphertext: Union[Ciphertext, EncryptedTensor],
        partial_decryptions: List[Union[dict, List[dict]]],
        verify: bool = False,
    ) -> Union[int, List[int], List[float]]:
        """
        Restore plaintext from partial decryptions of at least threshold many
            shareholders. Public key is enough, so anyone can combine them.
        Args:
            ciphertext (Ciphertext or EncryptedTensor): encrypted message
            partial_decryptions (list): outputs of partial_decrypt of shareholders
            verify (bool): set this to True to check zero-knowledge proofs of partial
                decryptions, and discard invalid or unproven ones. Default is False,
                then a cheating shareholder can cause a wrong plaintext silently.
                Supported by ElGamal, Exponential-ElGamal, EllipticCurve-ElGamal, and
                Paillier and Damgard-Jurik with keys generated with safe_primes=True.
        Returns:
            plaintext (int or tensor): restored message
        """
        self.__require_key("public_key", "combine partial decryptions")

        if isinstance(ciphertext, EncryptedTensor):
            plain_tensor = []
            for k, c in enumerate(ciphertext.fractions):
                abs_dividend = self.cs.combine_partial_decryptions(
                    ciphertext=c.abs_dividend,
                    partial_decryptions=[p[k]["abs_dividend"] for p in partial_decryptions],
                    verify=verify,
                )
                divisor = self.cs.combine_partial_decryptions(
                    ciphertext=c.divisor,
                    partial_decryptions=[p[k]["divisor"] for p in partial_decryptions],
                    verify=verify,
                )
                plain_tensor.append(c.sign * abs_dividend / divisor)
            return plain_tensor

        return self.cs.combine_partial_decryptions(
            ciphertext=ciphertext.value,
            partial_decryptions=partial_decryptions,
            verify=verify,
        )

    def verify_partial_decryption(
        self, ciphertext: Ciphertext, partial_decryption: dict
    ) -> bool:
        """
        Verify that a partial decryption is computed with the share of its shareholder.
            Public key is enough. Partial decryption must be created with prove=True.
            combine_partial_decryptions does this if verify=True and discards invalid
            ones, so this is useful to find a cheating shareholder.
            Supported by ElGamal, Exponential-ElGamal, EllipticCurve-ElGamal, and
            Paillier and Damgard-Jurik with keys generated with safe_primes=True.
        Args:
            ciphertext (Ciphertext): encrypted message
            partial_decryption (dict): output of partial_decrypt
        Returns:
            is valid (bool)
        """
        self.__require_key("public_key", "verify partial decryption")
        return self.cs.verify_partial_decryption(
            ciphertext=ciphertext.value, partial_decryption=partial_decryption
        )

    def decrypt_with_proof(self, ciphertext: Ciphertext) -> Tuple[int, dict]:
        """
        Decrypt a ciphertext and prove that the decryption is correct, without revealing
            the private key. Runs on private key owner side, e.g. a tallying authority
            announcing the result of an election. Supported by ElGamal,
            Exponential-ElGamal (keys generated with prime_order=True),
            EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
        Args:
            ciphertext (Ciphertext): encrypted message
        Returns:
            plaintext (int): restored message, same as decrypt
            proof (dict): proof of correct decryption, to be shared with the verifier
        """
        self.__require_key("private_key", "perform decryption")
        self.__require_key("public_key", "perform decryption")
        if not isinstance(ciphertext, Ciphertext):
            raise ValueError("Proofs of correct decryption are supported for Ciphertext only")
        return self.cs.decrypt_with_proof(ciphertext=ciphertext.value)

    def verify_decryption(self, ciphertext: Ciphertext, plaintext: int, proof: dict) -> bool:
        """
        Verify that a ciphertext is decrypted to the given plaintext. Public key is
            enough, so anyone can check the announced plaintext.
        Args:
            ciphertext (Ciphertext): encrypted message
            plaintext (int): claimed plaintext
            proof (dict): output of decrypt_with_proof
        Returns:
            is valid (bool)
        """
        self.__require_key("public_key", "verify decryption")
        return self.cs.verify_decryption(
            ciphertext=ciphertext.value, plaintext=plaintext, proof=proof
        )

    def encrypt_with_proof(
        self, plaintext: int, values: Optional[List[int]] = None, context: Any = None
    ) -> Tuple[Ciphertext, dict]:
        """
        Encrypt a plaintext and prove that it is one of the allowed values, without
            revealing which one. For instance, a voter proves that the encrypted vote
            is 0 or 1, so cannot cheat with a vote of 100 in the homomorphic tally.
            Public key is enough. Supported by Exponential-ElGamal (keys generated
            with prime_order=True), EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
        Args:
            plaintext (int): message to encrypt, must be one of values
            values (list of int): allowed values. Default is [0, 1].
            context (any): public data bound to the proof, e.g. id of the voter, so that
                the proof cannot be copied for another context. Must be json serializable.
        Returns:
            ciphertext (Ciphertext): encrypted message
            proof (dict): proof that ciphertext encrypts one of values
        """
        self.__require_key("public_key", "perform encryption")
        values = self.__normalize_values(values)
        if not isinstance(plaintext, int) or isinstance(plaintext, bool):
            raise ValueError("Plaintext must be an integer")
        plaintext = phe_utils.normalize_input(value=plaintext, modulo=self.cs.plaintext_modulo)
        if plaintext not in values:
            raise ValueError("Plaintext must be one of the allowed values")

        ciphertext, proof = self.cs.encrypt_with_proof(
            plaintext=plaintext, values=values, context=context
        )
        return self.__public_ciphertext(value=ciphertext), proof

    def verify_ciphertext(
        self,
        ciphertext: Ciphertext,
        proof: dict,
        values: Optional[List[int]] = None,
        context: Any = None,
    ) -> bool:
        """
        Verify that a ciphertext encrypts one of the allowed values without decrypting it.
            Public key is enough, e.g. anyone can check the ballots of an election.
        Args:
            ciphertext (Ciphertext): encrypted message
            proof (dict): output of encrypt_with_proof
            values (list of int): allowed values. Default is [0, 1].
            context (any): public data that the proof is expected to be bound to
        Returns:
            is valid (bool)
        """
        self.__require_key("public_key", "verify ciphertext")
        values = self.__normalize_values(values)
        if not isinstance(ciphertext, Ciphertext):
            return False
        return self.cs.verify_ciphertext(
            ciphertext=ciphertext.value, proof=proof, values=values, context=context
        )

    def encrypt_with_proof_of_knowledge(
        self, plaintext: int, context: Any = None
    ) -> Tuple[Ciphertext, dict]:
        """
        Encrypt a plaintext and prove that the encryptor knows it, without revealing it.
            For instance, a bidder of a sealed-bid auction proves knowledge of the bid,
            so nobody can outbid by copying someone else's encrypted bid and adding 1 to
            it homomorphically. Public key is enough. Supported by ElGamal and
            Exponential-ElGamal (keys generated with prime_order=True),
            EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
        Args:
            plaintext (int): message to encrypt
            context (any): public data bound to the proof, e.g. id of the encryptor, so that
                the proof cannot be copied for another context. Must be json serializable.
        Returns:
            ciphertext (Ciphertext): encrypted message
            proof (dict): proof of knowledge of plaintext
        """
        self.__require_key("public_key", "perform encryption")
        if not isinstance(plaintext, int) or isinstance(plaintext, bool):
            raise ValueError("Plaintext must be an integer")
        ciphertext, proof = self.cs.encrypt_with_proof_of_knowledge(
            plaintext=phe_utils.normalize_input(value=plaintext, modulo=self.cs.plaintext_modulo),
            context=context,
        )
        return self.__public_ciphertext(value=ciphertext), proof

    def verify_knowledge(self, ciphertext: Ciphertext, proof: dict, context: Any = None) -> bool:
        """
        Verify that the encryptor of a ciphertext knows its plaintext without decrypting it.
            Public key is enough.
        Args:
            ciphertext (Ciphertext): encrypted message
            proof (dict): output of encrypt_with_proof_of_knowledge
            context (any): public data that the proof is expected to be bound to
        Returns:
            is valid (bool)
        """
        self.__require_key("public_key", "verify knowledge")
        if not isinstance(ciphertext, Ciphertext):
            return False
        return self.cs.verify_knowledge(ciphertext=ciphertext.value, proof=proof, context=context)

    def encrypt_one_hot(
        self, choice: int, options: int, context: Any = None
    ) -> Tuple[List[Ciphertext], dict]:
        """
        Encrypt a choice among options as a one-hot vector, i.e. 1 for the chosen option
            and 0 for others, and prove that exactly one option is chosen without revealing
            which one. For instance, a voter votes for one of many parties. Summing slots
            of all ballots homomorphically counts votes of each option separately, so the
            number of options is not limited. Public key is enough. Supported by
            Exponential-ElGamal (keys generated with prime_order=True),
            EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
        Args:
            choice (int): index of the chosen option in [0, options)
            options (int): number of options
            context (any): public data bound to the proof, e.g. id of the voter, so that
                the proof cannot be copied for another context. Must be json serializable.
        Returns:
            ciphertexts (list of Ciphertext): encrypted slots, one per option
            proof (dict): proof that slots are 0 or 1 and sum to 1
        """
        self.__require_key("public_key", "perform encryption")
        for value in [choice, options]:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError("Choice and number of options must be integers")
        if options < 1:
            raise ValueError("Number of options must be at least 1")
        if not 0 <= choice < options:
            raise ValueError(f"Choice must be in [0, {options})")
        if type(self.cs).prove_membership is Homomorphic.prove_membership:
            raise ValueError(
                f"{self.algorithm_name} does not support proving that a ciphertext"
                " encrypts one of given values"
            )

        ciphertexts, proof = zkp.prove_one_hot(
            cs=self.cs,
            choice=choice,
            options=options,
            values=self.__normalize_values([0, 1]),
            context=context,
        )
        return [self.__public_ciphertext(value=c) for c in ciphertexts], proof

    def verify_one_hot(
        self, ciphertexts: List[Ciphertext], proof: dict, context: Any = None
    ) -> bool:
        """
        Verify that encrypted slots are a one-hot vector, i.e. exactly one option is chosen,
            without decrypting them. Public key is enough.
        Args:
            ciphertexts (list of Ciphertext): encrypted slots, one per option
            proof (dict): output of encrypt_one_hot
            context (any): public data that the proof is expected to be bound to
        Returns:
            is valid (bool)
        """
        self.__require_key("public_key", "verify one-hot ciphertexts")
        if not isinstance(ciphertexts, list) or not all(
            isinstance(c, Ciphertext) for c in ciphertexts
        ):
            return False
        return zkp.verify_one_hot(
            cs=self.cs,
            ciphertexts=[c.value for c in ciphertexts],
            proof=proof,
            values=self.__normalize_values([0, 1]),
            context=context,
        )

    def encrypt_with_range_proof(
        self, plaintext: int, low: int, high: int, context: Any = None
    ) -> Tuple[Ciphertext, dict]:
        """
        Encrypt a plaintext and prove that it is in [low, high], without revealing it.
            For instance, an employee proves that the encrypted salary is in a sensible
            range, so cannot skew the average of salaries with a negative or huge value.
            Public key is enough. Supported by Exponential-ElGamal (keys generated
            with prime_order=True), EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
            Proof size grows with the bit length of high - low.
        Args:
            plaintext (int): message to encrypt in [low, high]
            low (int): lower bound of the range
            high (int): upper bound of the range
            context (any): public data bound to the proof, e.g. id of the employee, so that
                the proof cannot be copied for another context. Must be json serializable.
        Returns:
            ciphertext (Ciphertext): encrypted message
            proof (dict): proof that ciphertext encrypts a value in [low, high]
        """
        self.__require_key("public_key", "perform encryption")
        values = self.__normalize_range(low=low, high=high)
        if not isinstance(plaintext, int) or isinstance(plaintext, bool):
            raise ValueError("Plaintext must be an integer")
        if not low <= plaintext <= high:
            raise ValueError(f"Plaintext must be in [{low}, {high}]")

        ciphertext, proof = zkp.prove_range(
            cs=self.cs, plaintext=plaintext, low=low, high=high, values=values, context=context
        )
        return self.__public_ciphertext(value=ciphertext), proof

    def verify_range(
        self, ciphertext: Ciphertext, proof: dict, low: int, high: int, context: Any = None
    ) -> bool:
        """
        Verify that a ciphertext encrypts a value in [low, high] without decrypting it.
            Public key is enough.
        Args:
            ciphertext (Ciphertext): encrypted message
            proof (dict): output of encrypt_with_range_proof
            low (int): lower bound of the range
            high (int): upper bound of the range
            context (any): public data that the proof is expected to be bound to
        Returns:
            is valid (bool)
        """
        self.__require_key("public_key", "verify range")
        values = self.__normalize_range(low=low, high=high)
        if not isinstance(ciphertext, Ciphertext):
            return False
        return zkp.verify_range(
            cs=self.cs,
            ciphertext=ciphertext.value,
            proof=proof,
            low=low,
            high=high,
            values=values,
            context=context,
        )

    def __normalize_range(self, low: int, high: int) -> List[int]:
        """
        Validate bounds of a range proof, and normalize low, 0 and 1 as encrypt does
        Args:
            low (int): lower bound of the range
            high (int): upper bound of the range
        Returns:
            normalized low, 0 and 1 (list of int)
        """
        for bound in [low, high]:
            if not isinstance(bound, int) or isinstance(bound, bool):
                raise ValueError("Bounds of the range must be integers")
        if low > high:
            raise ValueError(f"Lower bound {low} must not be greater than upper bound {high}")
        if high - low >= self.cs.plaintext_modulo:
            raise ValueError("Range must be narrower than the plaintext modulo")
        return [
            phe_utils.normalize_input(value=value, modulo=self.cs.plaintext_modulo)
            for value in [low, 0, 1]
        ]

    def __normalize_values(self, values: Optional[List[int]]) -> List[int]:
        """
        Validate allowed values of a proof and normalize them as encrypt does
        Args:
            values (list of int): allowed values. Default is [0, 1].
        Returns:
            normalized values (list of int)
        """
        values = [0, 1] if values is None else values
        if not isinstance(values, (list, tuple)) or len(values) == 0:
            raise ValueError("Allowed values must be a non-empty list of integers")
        if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
            raise ValueError("Allowed values must be a non-empty list of integers")
        normalized = [
            phe_utils.normalize_input(value=value, modulo=self.cs.plaintext_modulo)
            for value in values
        ]
        if len(set(normalized)) != len(normalized):
            raise ValueError("Allowed values must be distinct")
        return normalized

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
        self,
        encrypted_tensor: EncryptedTensor,
        decrypt: Optional[Callable[[Union[int, tuple, list]], int]] = None,
    ) -> Union[List[int], List[float]]:
        """
        Decrypt a given encrypted tensor
        Args:
            encrypted_tensor (list of encrypted tensor)
            decrypt (callable): decryption function. cryptosystem's decrypt is used if not set.
        Returns:
            List of plain tensors
        """
        decrypt = decrypt or (lambda c: self.cs.decrypt(ciphertext=c))
        plain_tensor = []
        for c in encrypted_tensor.fractions:
            if isinstance(c, Fraction) is False:
                raise ValueError("Ciphertext items must be type of Fraction")

            sign = c.sign
            abs_dividend = decrypt(c.abs_dividend)
            # dividend = self.cs.decrypt(ciphertext=c.dividend)

            # TODO: do I really need encrypted divisor? cannot I store current_precision
            divisor = decrypt(c.divisor)

            m = sign * abs_dividend / divisor

            plain_tensor.append(m)
        return plain_tensor

    def encrypt_decision_tree_input(
        self,
        bits: Optional[List[int]] = None,
        depth: Optional[int] = None,
        features: Optional[List[int]] = None,
        bit_length: Optional[int] = None,
    ) -> List[List[int]]:
        """
        Encrypt client's input of a decision tree owned by the server.
            Ishai-Paskin expects bits and depth, and Damgard-Geisler-Kroigaard expects
            features and bit_length.
        Args:
            bits (list of int): Ishai-Paskin only. input bits (answers to the questions)
                x_0, x_1, ... each 0 or 1
            depth (int): Ishai-Paskin only. maximum number of decisions on a path
                of the decision tree
            features (list of int): Damgard-Geisler-Kroigaard only. numeric features
                each in [0, 2^bit_length)
            bit_length (int): Damgard-Geisler-Kroigaard only. number of bits of
                features and thresholds
        Returns:
            encrypted input (list of list of int): to be sent to the tree owner
        """
        if self.cs.keys.get("public_key") is None:
            raise ValueError("You must have public key to perform encryption")

        uses_bits = bits is not None or depth is not None
        uses_features = features is not None or bit_length is not None

        if uses_bits and uses_features:
            raise ValueError(
                "Pass either bits and depth (Ishai-Paskin) or features and bit_length"
                " (Damgard-Geisler-Kroigaard), not both"
            )

        if uses_features:
            if features is None or bit_length is None:
                raise ValueError("features and bit_length must be passed together")
            return self.cs.encrypt_decision_tree_features(
                features=features, bit_length=bit_length
            )

        if bits is None or depth is None:
            raise ValueError("bits and depth must be passed together")
        return self.cs.encrypt_decision_tree_input(bits=bits, depth=depth)

    def evaluate_decision_tree(
        self, tree: Union[int, tuple], encrypted_input: List[List[int]]
    ) -> Ciphertext:
        """
        Evaluate a decision tree on encrypted input.
            Private key is not required. Only supported by Ishai-Paskin.
        Args:
            tree (int or tuple): leaf (int) or decision node
                (variable_index, tree_if_0, tree_if_1)
            encrypted_input (list of list of int): output of encrypt_decision_tree_input
        Returns:
            ciphertext (Ciphertext): encrypted output of the tree
        """
        if self.cs.keys.get("public_key") is None:
            raise ValueError(
                "You must have public key to perform decision tree evaluation"
            )

        output = self.cs.evaluate_decision_tree(
            tree=tree, encrypted_input=encrypted_input
        )

        return self.__public_ciphertext(value=output)

    def encrypt_comparison_input(self, value: int, bit_length: int) -> List[int]:
        """
        Encrypt bits of client's value x to compare it with server's value y.
            1st step of secure comparison, runs on client side.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            value (int): client's value x in [0, 2^bit_length)
            bit_length (int): number of bits of compared values
        Returns:
            encrypted input (list of int): to be sent to the server
        """
        self.__require_key("public_key", "perform encryption")
        return self.cs.encrypt_comparison_input(value=value, bit_length=bit_length)

    def evaluate_comparison(self, encrypted_input: List[int], value: int) -> List[int]:
        """
        Compare client's encrypted value x with server's value y.
            2nd step of secure comparison, runs on server side. Private key is not
            required and server learns nothing about x.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            encrypted_input (list of int): output of encrypt_comparison_input
            value (int): server's value y in [0, 2^bit_length)
        Returns:
            encrypted result (list of int): to be sent back to the client
        """
        self.__require_key("public_key", "perform secure comparison")
        return self.cs.evaluate_comparison(encrypted_input=encrypted_input, value=value)

    def decrypt_comparison(self, encrypted_result: List[int]) -> bool:
        """
        Restore the result of secure comparison.
            3rd step of secure comparison, runs on client side.
            Client learns only whether x <= y, but not y.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            encrypted_result (list of int): output of evaluate_comparison
        Returns:
            result (bool): True if x <= y
        """
        self.__require_key("private_key", "perform decryption")
        return self.cs.decrypt_comparison(encrypted_result=encrypted_result)

    def evaluate_decision_tree_comparisons(
        self, tree: Union[int, tuple], encrypted_features: List[List[int]]
    ) -> Tuple[List[List[int]], dict]:
        """
        Compare encrypted features with thresholds of all decision nodes.
            2nd step of private decision tree evaluation, runs on server side.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            tree (int or tuple): leaf label (int) or decision node
                (feature_index, threshold, tree_if_less_or_equal, tree_if_greater)
            encrypted_features (list of list of int): output of encrypt_decision_tree_input
        Returns:
            encrypted comparisons (list of list of int): to be sent to the client
            server state (dict): must be kept secret on server side for the 4th step
        """
        self.__require_key("public_key", "perform decision tree evaluation")
        return self.cs.evaluate_decision_tree_comparisons(
            tree=tree, encrypted_features=encrypted_features
        )

    def answer_decision_tree_comparisons(
        self, encrypted_comparisons: List[List[int]]
    ) -> List[int]:
        """
        Answer server's comparisons in encrypted form. Comparisons are randomly flipped
            by the server, so client does not learn the path in the tree.
            3rd step of private decision tree evaluation, runs on client side.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            encrypted_comparisons (list of list of int): output of
                evaluate_decision_tree_comparisons
        Returns:
            encrypted answers (list of int): to be sent to the server
        """
        self.__require_key("private_key", "perform decryption")
        return self.cs.answer_decision_tree_comparisons(
            encrypted_comparisons=encrypted_comparisons
        )

    def evaluate_decision_tree_leaves(
        self, server_state: dict, encrypted_answers: List[int]
    ) -> List[Tuple[int, int]]:
        """
        Find the reached leaf in encrypted form.
            4th step of private decision tree evaluation, runs on server side.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            server_state (dict): output of evaluate_decision_tree_comparisons
            encrypted_answers (list of int): output of answer_decision_tree_comparisons
        Returns:
            encrypted leaves (list of tuple of int): to be sent to the client
        """
        self.__require_key("public_key", "perform decision tree evaluation")
        return self.cs.evaluate_decision_tree_leaves(
            server_state=server_state, encrypted_answers=encrypted_answers
        )

    def decrypt_decision_tree_output(
        self, encrypted_leaves: List[Tuple[int, int]]
    ) -> int:
        """
        Restore the label of the reached leaf. Client learns only this label.
            Last step of private decision tree evaluation, runs on client side.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            encrypted_leaves (list of tuple of int): output of evaluate_decision_tree_leaves
        Returns:
            label (int): label of the reached leaf
        """
        self.__require_key("private_key", "perform decryption")
        return self.cs.decrypt_decision_tree_output(encrypted_leaves=encrypted_leaves)

    def evaluate_argmax(
        self,
        encrypted_values: List[Union[Ciphertext, int]],
        bit_length: int,
        client: Callable[[dict], List[int]],
    ) -> Ciphertext:
        """
        Find the index of the maximum of encrypted values without decrypting them.
            Runs on server side and talks to the client (private key owner) through the
            client callable. Client learns only the index, and server learns nothing.
            Index of the first maximum is returned on ties.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            encrypted_values (list of Ciphertext): encrypted values in [0, 2^bit_length)
            bit_length (int): number of bits of the values
            client (callable): sends a message (dict) to the client, and returns the
                output of the client's answer_argmax. Locally, it can be client's
                answer_argmax directly. Otherwise, wrap your network call with it.
        Returns:
            encrypted index (Ciphertext): to be decrypted by the client
        """
        self.__require_key("public_key", "perform encrypted argmax")
        output = self.cs.evaluate_argmax(
            encrypted_values=[
                value.value if isinstance(value, Ciphertext) else value
                for value in encrypted_values
            ],
            bit_length=bit_length,
            client=client,
        )

        return self.__public_ciphertext(value=output)

    def answer_argmax(self, message: dict) -> List[int]:
        """
        Answer a message of the server during encrypted argmax. Runs on client side.
            Every value decrypted here is masked with a uniformly random value.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            message (dict): message of the server
        Returns:
            response (list of int): to be sent back to the server
        """
        self.__require_key("private_key", "perform decryption")
        return self.cs.answer_argmax(message=message)

    def encrypt_knn_query(self, query: List[int]) -> dict:
        """
        Encrypt a query vector for encrypted k nearest neighbor search. Runs on client side,
            e.g. a user searching a face embedding in the gallery of a server.
            Embeddings must be quantized to integers, e.g. by scaling and rounding.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            query (list of int): query vector
        Returns:
            encrypted query (dict): to be sent to the server
        """
        self.__require_key("public_key", "perform encryption")
        self.__require_knn_support()
        if not isinstance(query, list) or len(query) == 0:
            raise ValueError("Query must be a non-empty list of integers")
        if any(not isinstance(x, int) or isinstance(x, bool) for x in query):
            raise ValueError("Query must be a non-empty list of integers")

        encrypted = nearest_neighbors.encrypt_query(cs=self.cs, query=query)
        return {
            "query": [self.__public_ciphertext(value=c) for c in encrypted["query"]],
            "norm": self.__public_ciphertext(value=encrypted["norm"]),
        }

    def evaluate_knn(
        self,
        encrypted_query: dict,
        database: List[List[int]],
        k: int,
        bit_length: int,
        client: Callable[[dict], List[int]],
        labels: Optional[List[int]] = None,
    ) -> dict:
        """
        Find the k nearest vectors of a database to an encrypted query by squared euclidean
            distance. Runs on server side and talks to the client (private key owner)
            through the client callable. Server learns nothing, and client learns only the
            indices, or the labels, of the k nearest vectors, but not the distances or the
            other vectors. Earlier index is returned on ties.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            encrypted_query (dict): output of encrypt_knn_query
            database (list of list of int): vectors of the server, in plain
            k (int): number of nearest vectors to find
            bit_length (int): squared distances between the query and vectors must be less
                than 2^bit_length, e.g. 24 for 128-dimensional embeddings of 8-bit entries.
            client (callable): sends a message (dict) to the client, and returns the output
                of the client's answer_knn. Locally, it can be client's answer_knn directly.
                Otherwise, wrap your network call with it.
            labels (list of int): optional labels of vectors, e.g. ids of people. If set,
                encrypted labels of the nearest vectors are returned as well.
        Returns:
            result (dict): "indices" (list of Ciphertext), and "labels" (list of Ciphertext)
                if labels are set, of the k nearest vectors from the nearest one.
                To be decrypted by the client.
        """
        self.__require_key("public_key", "perform encrypted nearest neighbor search")
        self.__require_knn_support()

        query = encrypted_query.get("query") if isinstance(encrypted_query, dict) else None
        if not isinstance(query, list) or len(query) == 0:
            raise ValueError("Encrypted query must be an output of encrypt_knn_query")
        if not isinstance(database, list) or len(database) == 0:
            raise ValueError("Database must be a non-empty list of vectors")
        if any(
            not isinstance(vector, list)
            or len(vector) != len(query)
            or any(not isinstance(x, int) or isinstance(x, bool) for x in vector)
            for vector in database
        ):
            raise ValueError(
                f"Every vector of the database must be a list of {len(query)} integers"
            )
        if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= len(database):
            raise ValueError(f"k must be in [1, {len(database)}]")
        if labels is not None and (
            not isinstance(labels, list)
            or len(labels) != len(database)
            or any(not isinstance(label, int) or isinstance(label, bool) for label in labels)
        ):
            raise ValueError("Labels must be a list of integers, one for each vector")
        if not isinstance(bit_length, int) or isinstance(bit_length, bool) or bit_length < 1:
            raise ValueError("Bit length must be a positive integer")
        # argmax validates that lifted values fit into the plaintext space
        largest_norm = max(sum(x * x for x in vector) for vector in database)
        if largest_norm >= 2**bit_length:
            raise ValueError(
                f"Squared norm {largest_norm} of a vector in the database does not fit into"
                f" {bit_length} bits"
            )

        result = nearest_neighbors.evaluate_knn(
            cs=self.cs,
            encrypted_query={
                "query": [c.value if isinstance(c, Ciphertext) else c for c in query],
                "norm": (
                    encrypted_query["norm"].value
                    if isinstance(encrypted_query["norm"], Ciphertext)
                    else encrypted_query["norm"]
                ),
            },
            database=database,
            k=k,
            bit_length=bit_length,
            client=client,
            labels=labels,
        )
        return {
            key: [self.__public_ciphertext(value=c) for c in ciphertexts]
            for key, ciphertexts in result.items()
        }

    def answer_knn(self, message: dict) -> List[int]:
        """
        Answer a message of the server during encrypted k nearest neighbor search.
            Runs on client side. Every value decrypted here is masked or shuffled,
            so client learns nothing but the final result.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            message (dict): message of the server
        Returns:
            response (list of int): to be sent back to the server
        """
        self.__require_key("private_key", "perform decryption")
        self.__require_knn_support()
        return nearest_neighbors.answer_knn(cs=self.cs, message=message)

    def evaluate_knn_distances(
        self,
        encrypted_query: List[CatalanoFioreCiphertext],
        encrypted_database: List[List[CatalanoFioreCiphertext]],
    ) -> List[CatalanoFioreCiphertext]:
        """
        Compute encrypted squared euclidean distances between an encrypted query and
            encrypted vectors. Runs on the side of an untrusted cloud storing the encrypted
            database of an owner, and requires the public key only. Both the query and the
            vectors are encrypted, so this requires boost="Catalano-Fiore" for one
            multiplication. Cloud learns nothing, and the owner finds the nearest vectors
            with decrypt_knn.
        Args:
            encrypted_query (list of CatalanoFioreCiphertext): encrypted query vector
            encrypted_database (list of list of CatalanoFioreCiphertext): encrypted vectors
        Returns:
            encrypted distances (list of CatalanoFioreCiphertext): one for each vector
        """
        self.__require_key("public_key", "compute encrypted distances")
        if self.__catalano_fiore is None:
            raise ValueError(
                "Encrypted distances between encrypted vectors require boost='Catalano-Fiore'"
            )

        def is_vector(vector) -> bool:
            return (
                isinstance(vector, list)
                and len(vector) > 0
                and all(
                    isinstance(c, CatalanoFioreCiphertext) and not c.is_multiplied
                    for c in vector
                )
            )

        if not is_vector(encrypted_query):
            raise ValueError("Encrypted query must be a non-empty list of encrypted integers")
        if not isinstance(encrypted_database, list) or len(encrypted_database) == 0:
            raise ValueError("Encrypted database must be a non-empty list of vectors")
        if any(
            not is_vector(vector) or len(vector) != len(encrypted_query)
            for vector in encrypted_database
        ):
            raise ValueError(
                f"Every vector of the database must be a list of {len(encrypted_query)}"
                " encrypted integers"
            )

        distances = []
        for vector in encrypted_database:
            total = None
            for q, x in zip(encrypted_query, vector):
                difference = q - x
                square = difference * difference
                total = square if total is None else total + square
            distances.append(total)
        return distances

    def decrypt_knn(self, encrypted_distances: List[CatalanoFioreCiphertext], k: int) -> dict:
        """
        Find the k nearest vectors from encrypted distances computed by
            evaluate_knn_distances. Runs on owner side, and requires the private key.
        Args:
            encrypted_distances (list of CatalanoFioreCiphertext): output of
                evaluate_knn_distances
            k (int): number of nearest vectors to find
        Returns:
            result (dict): "indices" and "distances" of the k nearest vectors from the
                nearest one. Earlier index is returned on ties.
        """
        self.__require_key("private_key", "perform decryption")
        if not isinstance(encrypted_distances, list) or len(encrypted_distances) == 0:
            raise ValueError("Encrypted distances must be a non-empty list")
        if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= len(encrypted_distances):
            raise ValueError(f"k must be in [1, {len(encrypted_distances)}]")

        distances = [self.decrypt(c) for c in encrypted_distances]
        indices = sorted(range(len(distances)), key=lambda i: (distances[i], i))[:k]
        return {"indices": indices, "distances": [distances[i] for i in indices]}

    def encrypt_update(
        self, update: List[Union[int, float]], max_value: Union[int, float], max_clients: int
    ) -> dict:
        """
        Encrypt a model update of a client for secure aggregation in federated learning.
            Values are quantized with the precision of this cryptosystem, and many of them
            are packed into a single ciphertext, so an update needs far fewer ciphertexts
            than its length. Public key is enough. Clients must use the same key, length,
            precision, max_value and max_clients. Supported by Paillier and Damgard-Jurik.
        Args:
            update (list of int or float): model update, e.g. gradients or weights
            max_value (int or float): absolute values of the update must be at most this,
                e.g. the clipping bound of gradients
            max_clients (int): maximum number of updates to be aggregated. Slots of
                ciphertexts are wide enough to sum this many updates without overflow.
        Returns:
            encrypted update (dict): chunks of ciphertexts, the layout of packing, and
                the number of updates it contains
        """
        self.__require_key("public_key", "perform encryption")
        self.__require_aggregation_support()
        if not isinstance(update, list):
            raise ValueError("Update must be a list of numbers")

        layout = secure_aggregation.build_layout(
            length=len(update),
            precision=self.precision,
            max_value=max_value,
            max_clients=max_clients,
            modulo=self.cs.plaintext_modulo,
        )
        plaintexts = secure_aggregation.pack(update=update, layout=layout)
        return {
            "chunks": [
                self.__public_ciphertext(value=self.cs.encrypt(plaintext=plaintext))
                for plaintext in plaintexts
            ],
            "layout": layout,
            "count": 1,
        }

    def aggregate_updates(self, encrypted_updates: List[dict]) -> dict:
        """
        Sum encrypted updates of clients chunk by chunk. Runs on server side, and requires
            the public key only. Server learns nothing about updates or their sum.
        Args:
            encrypted_updates (list of dict): outputs of encrypt_update or aggregate_updates
        Returns:
            encrypted sum (dict): chunks of ciphertexts of the sum, the layout of packing,
                and the number of updates it contains
        """
        self.__require_key("public_key", "aggregate updates")
        self.__require_aggregation_support()
        if not isinstance(encrypted_updates, list) or len(encrypted_updates) == 0:
            raise ValueError("Encrypted updates must be a non-empty list")

        layout = encrypted_updates[0]["layout"]
        if any(update["layout"] != layout for update in encrypted_updates):
            raise ValueError(
                "Encrypted updates must have the same layout, i.e. the same length,"
                " precision, max_value and max_clients"
            )
        count = sum(update["count"] for update in encrypted_updates)
        if count > layout["max_clients"]:
            raise ValueError(
                f"Sum of {count} updates would overflow slots packed for at most"
                f" {layout['max_clients']} clients"
            )

        chunks = list(encrypted_updates[0]["chunks"])
        for update in encrypted_updates[1:]:
            chunks = [total + chunk for total, chunk in zip(chunks, update["chunks"])]
        return {"chunks": chunks, "layout": layout, "count": count}

    def partial_decrypt_aggregate(self, encrypted_sum: dict, prove: bool = False) -> List[dict]:
        """
        Decrypt an encrypted sum of updates partially with the share of a shareholder,
            e.g. a member of a committee of clients. Shareholders decrypt sums only,
            never individual updates.
        Args:
            encrypted_sum (dict): output of aggregate_updates
            prove (bool): set this to True to attach proofs of correct partial decryption.
                Keys must be generated with safe_primes=True.
        Returns:
            partial decryptions (list of dict): one for each chunk, to be sent to the combiner
        """
        self.__require_aggregation_support()
        return [self.partial_decrypt(chunk, prove=prove) for chunk in encrypted_sum["chunks"]]

    def combine_aggregate(
        self, encrypted_sum: dict, partial_decryptions: List[List[dict]], verify: bool = False
    ) -> dict:
        """
        Restore the sum and the mean of updates from partial decryptions of at least
            threshold many shareholders. Public key is enough.
        Args:
            encrypted_sum (dict): output of aggregate_updates
            partial_decryptions (list of list of dict): outputs of partial_decrypt_aggregate
                of shareholders
            verify (bool): set this to True to check proofs of partial decryptions, and
                discard invalid or unproven ones
        Returns:
            aggregate (dict): "sum" and "mean" of updates, and the number of updates "count"
        """
        self.__require_key("public_key", "combine partial decryptions")
        self.__require_aggregation_support()
        plaintexts = [
            self.cs.combine_partial_decryptions(
                ciphertext=chunk.value,
                partial_decryptions=[partials[i] for partials in partial_decryptions],
                verify=verify,
            )
            for i, chunk in enumerate(encrypted_sum["chunks"])
        ]
        return self.__unpack_aggregate(encrypted_sum=encrypted_sum, plaintexts=plaintexts)

    def decrypt_aggregate(self, encrypted_sum: dict) -> dict:
        """
        Restore the sum and the mean of updates with the private key, if a single party
            holds it instead of a committee
        Args:
            encrypted_sum (dict): output of aggregate_updates
        Returns:
            aggregate (dict): "sum" and "mean" of updates, and the number of updates "count"
        """
        self.__require_key("private_key", "perform decryption")
        self.__require_aggregation_support()
        plaintexts = [self.cs.decrypt(ciphertext=chunk.value) for chunk in encrypted_sum["chunks"]]
        return self.__unpack_aggregate(encrypted_sum=encrypted_sum, plaintexts=plaintexts)

    def __unpack_aggregate(self, encrypted_sum: dict, plaintexts: List[int]) -> dict:
        """
        Unpack decrypted chunks of a sum of updates
        """
        count = encrypted_sum["count"]
        total = secure_aggregation.unpack(
            plaintexts=plaintexts, layout=encrypted_sum["layout"], count=count
        )
        return {"sum": total, "mean": [x / count for x in total], "count": count}

    def __require_aggregation_support(self) -> None:
        """
        Raise an error if the algorithm does not support secure aggregation
        """
        if self.algorithm_name not in [Algorithm.Paillier, Algorithm.DamgardJurik]:
            raise ValueError(
                f"{self.algorithm_name} does not support secure aggregation."
                " Use Paillier or Damgard-Jurik instead."
            )

    def evaluate_hyperplane(
        self,
        encrypted_features: List[Ciphertext],
        weights: List[List[int]],
        bit_length: int,
        client: Callable[[dict], List[int]],
        biases: Optional[List[int]] = None,
    ) -> Ciphertext:
        """
        Classify encrypted features with a private linear model, i.e. find the class of the
            greatest score <w_i, x> + b_i, e.g. logistic regression or a linear SVM. Runs on
            server side and talks to the client (private key owner) through the client
            callable. Client learns only the predicted class, and server learns nothing.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            encrypted_features (list of Ciphertext): features encrypted by the client.
                Floats must be quantized to integers, e.g. by scaling and rounding.
            weights (list of list of int): integer weights of each class
            bit_length (int): absolute values of scores must be less than 2^bit_length
            client (callable): sends a message (dict) to the client, and returns the output
                of the client's answer_argmax
            biases (list of int): optional integer bias of each class
        Returns:
            encrypted class (Ciphertext): index of the predicted class, to be decrypted
                by the client. Earlier class is returned on ties.
        """
        self.__require_key("public_key", "perform encrypted classification")
        self.__require_classifier_support()
        classifiers.validate_model_shape(weights=weights)
        biases = biases if biases is not None else [0] * len(weights)
        values = [x for w in weights for x in w] + list(biases)
        if any(not isinstance(x, int) or isinstance(x, bool) for x in values):
            raise ValueError("Weights and biases must be integers. Quantize them first.")
        if len(biases) != len(weights):
            raise ValueError("There must be a bias for each class")
        if (
            not isinstance(encrypted_features, list)
            or len(encrypted_features) != len(weights[0])
            or any(not isinstance(c, Ciphertext) for c in encrypted_features)
        ):
            raise ValueError(f"Encrypted features must be a list of {len(weights[0])} ciphertexts")
        if not isinstance(bit_length, int) or isinstance(bit_length, bool) or bit_length < 1:
            raise ValueError("Bit length must be a positive integer")

        output = classifiers.evaluate_hyperplane(
            cs=self.cs,
            encrypted_features=[c.value for c in encrypted_features],
            weights=weights,
            biases=biases,
            bit_length=bit_length,
            client=client,
        )
        return self.__public_ciphertext(value=output)

    def encrypt_naive_bayes_input(
        self, features: List[int], domain_sizes: List[int]
    ) -> List[List[Ciphertext]]:
        """
        Encrypt categorical features for naive bayes classification as one-hot vectors.
            Runs on client side. Only supported by Damgard-Geisler-Kroigaard.
        Args:
            features (list of int): value of each feature in [0, domain size)
            domain_sizes (list of int): number of values of each feature, which the
                server shares as a part of its model
        Returns:
            encrypted input (list of list of Ciphertext): to be sent to the server
        """
        self.__require_key("public_key", "perform encryption")
        self.__require_classifier_support()
        if (
            not isinstance(features, list)
            or not isinstance(domain_sizes, list)
            or len(features) == 0
            or len(features) != len(domain_sizes)
        ):
            raise ValueError("There must be a domain size for each feature")
        for feature, size in zip(features, domain_sizes):
            if not isinstance(size, int) or isinstance(size, bool) or size < 1:
                raise ValueError("Domain sizes must be positive integers")
            if not isinstance(feature, int) or isinstance(feature, bool) or not 0 <= feature < size:
                raise ValueError(f"Feature {feature} must be an integer in [0, {size})")

        encrypted = classifiers.encrypt_naive_bayes_input(
            cs=self.cs, features=features, domain_sizes=domain_sizes
        )
        return [[self.__public_ciphertext(value=c) for c in one_hot] for one_hot in encrypted]

    def evaluate_naive_bayes(
        self,
        encrypted_input: List[List[Ciphertext]],
        priors: List[float],
        likelihoods: List[List[List[float]]],
        client: Callable[[dict], List[int]],
        precision: int = 3,
    ) -> Ciphertext:
        """
        Classify encrypted categorical features with a private naive bayes model, i.e. find
            the class of the greatest log P(c) + sum of log P(x_j | c). Runs on server side
            and talks to the client (private key owner) through the client callable.
            Client learns only the predicted class, and server learns nothing.
            Only supported by Damgard-Geisler-Kroigaard.
        Args:
            encrypted_input (list of list of Ciphertext): output of encrypt_naive_bayes_input
            priors (list of float): P(c) of each class
            likelihoods (list of list of list of float): P(x_j = v | c) for class c,
                feature j and value v, i.e. likelihoods[c][j][v]. Probabilities must be
                positive, e.g. smoothed with Laplace smoothing.
            client (callable): sends a message (dict) to the client, and returns the output
                of the client's answer_argmax
            precision (int): number of decimal digits kept from log probabilities.
                Default is 3. Greater values need more bits for scores.
        Returns:
            encrypted class (Ciphertext): index of the predicted class, to be decrypted
                by the client. Earlier class is returned on ties.
        """
        self.__require_key("public_key", "perform encrypted classification")
        self.__require_classifier_support()
        classifiers.validate_model_shape(likelihoods=likelihoods)
        if not isinstance(priors, list) or len(priors) != len(likelihoods):
            raise ValueError("There must be a prior for each class")
        domain_sizes = [len(values) for values in likelihoods[0]]
        if (
            not isinstance(encrypted_input, list)
            or [len(one_hot) for one_hot in encrypted_input] != domain_sizes
            or any(not isinstance(c, Ciphertext) for one_hot in encrypted_input for c in one_hot)
        ):
            raise ValueError(
                f"Encrypted input must be one-hot vectors of domain sizes {domain_sizes}"
            )
        if not isinstance(precision, int) or isinstance(precision, bool) or precision < 0:
            raise ValueError("Precision must be a non-negative integer")

        quantized_priors, quantized_likelihoods, bit_length = classifiers.quantize_naive_bayes(
            priors=priors, likelihoods=likelihoods, precision=precision
        )
        output = classifiers.evaluate_naive_bayes(
            cs=self.cs,
            encrypted_input=[[c.value for c in one_hot] for one_hot in encrypted_input],
            priors=quantized_priors,
            likelihoods=quantized_likelihoods,
            bit_length=bit_length,
            client=client,
        )
        return self.__public_ciphertext(value=output)

    def __require_classifier_support(self) -> None:
        """
        Raise an error if the algorithm does not support encrypted classification
        """
        if self.algorithm_name != Algorithm.DamgardGeislerKroigaard:
            raise ValueError(
                f"{self.algorithm_name} does not support encrypted classification."
                " Use Damgard-Geisler-Kroigaard instead."
            )

    def __require_knn_support(self) -> None:
        """
        Raise an error if the algorithm does not support encrypted nearest neighbor search
        """
        if self.algorithm_name != Algorithm.DamgardGeislerKroigaard:
            raise ValueError(
                f"{self.algorithm_name} does not support encrypted nearest neighbor search."
                " Use Damgard-Geisler-Kroigaard instead."
            )

    def __require_key(self, key_type: str, action: str) -> None:
        """
        Raise an error if the cryptosystem does not have the given key
        Args:
            key_type (str): public_key or private_key
            action (str): description of the action requiring the key
        """
        if self.cs.keys.get(key_type) is None:
            raise ValueError(f"You must have {key_type.replace('_', ' ')} to {action}")

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

        if isinstance(ciphertext, CatalanoFioreCiphertext):
            raise ValueError(
                "Ciphertexts supporting multiplication cannot be regenerated. "
                "Encrypt the plaintext again instead."
            )

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
