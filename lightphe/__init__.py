# built-in dependencies
import time
import json
from typing import Optional, Union, List, Tuple, Callable
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
                | Gentry-Halevi-Vaikuntanathan
            keys (dict): optional private-public key pair
            key_file (str): if keys were exported already, you can load them into cryptosystem
            key_size (int): key size in bits. For Regev, it is the lattice dimension.
                For Brakerski-Vaikuntanathan, it is the ring degree.
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
                'Brakerski-Vaikuntanathan', 'Freeman-Boneh-Goh-Nissim' or
                'Gentry-Halevi-Vaikuntanathan'.
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
        """
        self.algorithm_name = algorithm_name
        self.precision = precision
        self.form = form
        self.curve = curve

        if key_file is not None:
            keys = self.restore_keys(target_file=key_file)

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
        )

        # Catalano-Fiore transform wraps a copy of this instance without the transform
        self.__catalano_fiore: Optional[CatalanoFiore] = None
        if boost is not None:
            if boost != CATALANO_FIORE:
                raise ValueError(
                    f"Unknown boost {boost}. Options are: {CATALANO_FIORE}"
                )
            self.__catalano_fiore = CatalanoFiore(copy.copy(self))

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
                | Gentry-Halevi-Vaikuntanathan
                Default is Paillier.
            keys (dict): optional private-public key pair
            key_file (str): if keys are exported, you can load them into cryptosystem
            key_size (int): key size in bits. For Regev, it is the lattice dimension.
                For Brakerski-Vaikuntanathan, it is the ring degree.
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
                'Brakerski-Vaikuntanathan', 'Freeman-Boneh-Goh-Nissim' or
                'Gentry-Halevi-Vaikuntanathan'.
            max_tries (int): maximum attempts to generate keys. Default is 10000.
                RSA, Benaloh, Naccache-Stern, Goldwasser-Micali, Boneh-Goh-Nissim,
                Joye-Libert, Castagnos-Laguillaumie, Damgard-Geisler-Kroigaard,
                Bresson-Catalano-Pointcheval and Camenisch-Shoup algorithms
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

        public_keys = self.cs.keys.copy()
        if public_keys.get("private_key") is not None:
            del public_keys["private_key"]

        return Ciphertext(
            algorithm_name=self.algorithm_name, keys=public_keys, value=output
        )

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

        public_keys = self.cs.keys.copy()
        if public_keys.get("private_key") is not None:
            del public_keys["private_key"]

        return Ciphertext(
            algorithm_name=self.algorithm_name, keys=public_keys, value=output
        )

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
