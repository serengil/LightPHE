# built-in dependencies
import copy
import secrets
from typing import List, Optional, Tuple, Union, TYPE_CHECKING

# project dependencies
from lightphe.models.Algorithm import Algorithm
from lightphe.models.Ciphertext import Ciphertext

if TYPE_CHECKING:
    from lightphe import LightPHE

# name of the transform as boost argument of LightPHE
BOOST_NAME = "Catalano-Fiore"

# additively homomorphic algorithms whose plaintext space Z_M is public, and which can
# decrypt any value in it
SUPPORTED_ALGORITHMS = [
    Algorithm.Paillier,
    Algorithm.DamgardJurik,
    Algorithm.BressonCatalanoPointcheval,
    Algorithm.CamenischShoup,
    Algorithm.EllipticCurvePaillier,
    Algorithm.JoyeLibert,
    Algorithm.CastagnosLaguillaumie,
    Algorithm.NaccacheStern,
    Algorithm.Benaloh,
    Algorithm.DamgardGeislerKroigaard,
]

# reasons of algorithms that cannot be upgraded
UNSUPPORTED_REASONS = {
    Algorithm.ExponentialElGamal: "its decryption solves discrete logarithm, which is"
    " infeasible for the uniformly random values the transform encrypts",
    Algorithm.EllipticCurveElGamal: "its decryption solves discrete logarithm, which is"
    " infeasible for the uniformly random values the transform encrypts",
    Algorithm.OkamotoUchiyama: "its plaintext modulus p is secret, so the encryptor cannot"
    " compute m - b mod p",
    Algorithm.Regev: "multiplying with uniformly random constants exceeds its noise budget",
    Algorithm.GoldwasserMicali: "it encrypts integers bit by bit and supports xor only,"
    " without multiplication with a constant",
    Algorithm.BonehGohNissim: "it already supports one multiplication natively",
    Algorithm.BrakerskiVaikuntanathan: "it already supports one multiplication natively",
    Algorithm.FreemanBonehGohNissim: "it already supports one multiplication natively",
    Algorithm.GentryHaleviVaikuntanathan: "it already supports one multiplication natively",
}


class CatalanoFiore:
    """
    Catalano-Fiore transform upgrades a linearly homomorphic cryptosystem to support one
    homomorphic multiplication, i.e. evaluating degree-2 functions such as dot products
    of two encrypted vectors, variances or squared distances. It wraps a built LightPHE
    instance, and uses its public operations only: encryption, decryption, homomorphic
    addition and multiplication with a constant. So, the underlying cryptosystem is used
    as is, and the transform is as secure as it is.

    Plaintext space is Z_M, where M is the plaintext modulo of the underlying cryptosystem.
        - encryption of m: (a, Enc(b)) where b is uniformly random in Z_M and a = m - b.
            a is in clear, but reveals nothing as b is uniformly random and secret.
        - addition: (a1 + a2, Enc(b1) + Enc(b2))
        - multiplication: m1 m2 = a1 a2 + a1 b2 + a2 b1 + b1 b2, so the result is
            alpha = Enc(a1 a2) + a1 Enc(b2) + a2 Enc(b1), which encrypts m1 m2 - b1 b2,
            together with the pair (Enc(b1), Enc(b2)) to restore b1 b2 in decryption.
        - decryption of a multiplied ciphertext: Dec(alpha) + sum of Dec(Enc(b1)) Dec(Enc(b2))
            for all pairs.
    Multiplied ciphertexts can be added with each other, with non-multiplied ciphertexts
    and with plain constants, and they can be multiplied with plain constants. But they
    cannot be multiplied with ciphertexts again.

    Notice that a multiplied ciphertext keeps a pair of ciphertexts for every product it
    contains, so its size grows with the number of products summed. For instance, dot
    product of two encrypted vectors of length d has d pairs. The pairs also reveal which
    ciphertexts were multiplied, but not their values.

    Encryption and homomorphic operations require the public key only, and decryption
    requires the private key of the underlying cryptosystem. Only integers are supported.

    It is enabled with boost argument of LightPHE, e.g.
    LightPHE(algorithm_name="Paillier", boost="Catalano-Fiore"), whose encrypt and decrypt
    then use this class.
    Ref: Catalano, D., Fiore, D. (2015). Using Linearly-Homomorphic Encryption to Evaluate
        Degree-2 Functions on Encrypted Data. ACM CCS 2015.
    """

    def __init__(self, cs: "LightPHE"):
        """
        Args:
            cs (LightPHE): built cryptosystem of a supported additively homomorphic algorithm
        """
        algorithm_name = cs.algorithm_name
        if algorithm_name not in SUPPORTED_ALGORITHMS:
            reason = UNSUPPORTED_REASONS.get(algorithm_name, "it is not additively homomorphic")
            raise ValueError(
                f"Catalano-Fiore transform does not support {algorithm_name} because {reason}. "
                f"Supported algorithms are {', '.join(SUPPORTED_ALGORITHMS)}."
            )
        self.cs = cs
        self.plaintext_modulo: int = cs.cs.plaintext_modulo

        # ciphertexts keep a reference to the transform for homomorphic operations.
        # they must not carry the private key, as they are sent to other parties.
        if cs.cs.keys.get("private_key") is None:
            self.public: CatalanoFiore = self
        else:
            public_cs = cs.__class__(
                algorithm_name=algorithm_name,
                keys={"public_key": copy.deepcopy(cs.cs.keys["public_key"])},
                form=cs.form,
                curve=cs.curve,
            )
            self.public = CatalanoFiore(public_cs)

    def encrypt(self, plaintext: int) -> "CatalanoFioreCiphertext":
        """
        Encrypt a plaintext as (a, Enc(b)) where a = m - b and b is uniformly random
        Args:
            plaintext (int): message to encrypt. It is reduced modulo M.
        Returns:
            ciphertext (CatalanoFioreCiphertext): non-multiplied ciphertext
        """
        if not isinstance(plaintext, int) or isinstance(plaintext, bool):
            raise ValueError(
                "Catalano-Fiore transform supports integers only, "
                f"but plaintext is {type(plaintext).__name__}"
            )
        modulo = self.plaintext_modulo
        b = secrets.randbelow(modulo)
        return CatalanoFioreCiphertext(
            cf=self.public, a=(plaintext - b) % modulo, beta=self.cs.encrypt(plaintext=b)
        )

    def decrypt(self, ciphertext: "CatalanoFioreCiphertext") -> int:
        """
        Decrypt a ciphertext created by the transform. Requires the private key.
        Args:
            ciphertext (CatalanoFioreCiphertext): non-multiplied or multiplied ciphertext
        Returns:
            plaintext (int): restored message in [0, M)
        """
        if not isinstance(ciphertext, CatalanoFioreCiphertext):
            raise ValueError("Ciphertext must be created by Catalano-Fiore transform")
        if self.cs.cs.keys.get("private_key") is None:
            raise ValueError("You must have private key to perform decryption")

        modulo = self.plaintext_modulo
        if not ciphertext.is_multiplied:
            return (ciphertext.a + self.cs.decrypt(ciphertext.beta)) % modulo

        result = self.cs.decrypt(ciphertext.alpha)
        for beta1, beta2 in ciphertext.pairs:
            result += self.cs.decrypt(beta1) * self.cs.decrypt(beta2)
        return result % modulo


class CatalanoFioreCiphertext:
    """
    Ciphertext of Catalano-Fiore transform. It is either non-multiplied as (a, beta),
        or multiplied as (alpha, pairs).
    """

    def __init__(
        self,
        cf: CatalanoFiore,
        a: Optional[int] = None,
        beta: Optional[Ciphertext] = None,
        alpha: Optional[Ciphertext] = None,
        pairs: Optional[List[Tuple[Ciphertext, Ciphertext]]] = None,
    ):
        self.cf = cf
        self.a = a
        self.beta = beta
        self.alpha = alpha
        self.pairs = pairs if pairs is not None else []
        self.is_multiplied = alpha is not None

    def __repr__(self) -> str:
        if self.is_multiplied:
            return f"CatalanoFioreCiphertext(multiplied, {len(self.pairs)} pairs)"
        return "CatalanoFioreCiphertext(non-multiplied)"

    def __add__(
        self, other: Union["CatalanoFioreCiphertext", int]
    ) -> "CatalanoFioreCiphertext":
        """
        Homomorphic addition with another ciphertext or a plain constant
        """
        modulo = self.cf.plaintext_modulo

        if isinstance(other, int) and not isinstance(other, bool):
            # adding a plain constant requires no homomorphic operation for a non-multiplied one
            if not self.is_multiplied:
                return CatalanoFioreCiphertext(
                    cf=self.cf, a=(self.a + other) % modulo, beta=self.beta
                )
            return CatalanoFioreCiphertext(
                cf=self.cf,
                alpha=self.alpha + self.cf.cs.encrypt(plaintext=other % modulo),
                pairs=self.pairs,
            )

        self.__check_same_system(other)

        if not self.is_multiplied and not other.is_multiplied:
            return CatalanoFioreCiphertext(
                cf=self.cf, a=(self.a + other.a) % modulo, beta=self.beta + other.beta
            )

        first, second = self.to_multiplied(), other.to_multiplied()
        return CatalanoFioreCiphertext(
            cf=self.cf,
            alpha=first.alpha + second.alpha,
            pairs=first.pairs + second.pairs,
        )

    def __radd__(self, other: int) -> "CatalanoFioreCiphertext":
        # lets sum() start from 0
        return self.__add__(other)

    def __neg__(self) -> "CatalanoFioreCiphertext":
        return self * -1

    def __sub__(
        self, other: Union["CatalanoFioreCiphertext", int]
    ) -> "CatalanoFioreCiphertext":
        return self + (-other)

    def __rsub__(self, other: int) -> "CatalanoFioreCiphertext":
        return (-self) + other

    def __mul__(
        self, other: Union["CatalanoFioreCiphertext", int]
    ) -> "CatalanoFioreCiphertext":
        """
        Homomorphic multiplication with another ciphertext, or with a plain constant
        """
        modulo = self.cf.plaintext_modulo

        if isinstance(other, int) and not isinstance(other, bool):
            constant = other % modulo
            if not self.is_multiplied:
                return CatalanoFioreCiphertext(
                    cf=self.cf, a=(self.a * constant) % modulo, beta=self.beta * constant
                )
            # scaling the first ciphertext of each pair scales the product b1 b2
            return CatalanoFioreCiphertext(
                cf=self.cf,
                alpha=self.alpha * constant,
                pairs=[(beta1 * constant, beta2) for beta1, beta2 in self.pairs],
            )

        if not isinstance(other, CatalanoFioreCiphertext):
            raise ValueError(
                "Catalano-Fiore ciphertexts can be multiplied with a ciphertext or an integer, "
                f"but it is {type(other).__name__}"
            )
        self.__check_same_system(other)

        if self.is_multiplied or other.is_multiplied:
            raise ValueError(
                "Catalano-Fiore transform supports only one multiplication. "
                "Multiplied ciphertexts cannot be multiplied with ciphertexts again."
            )

        # Enc(a1 a2) + a1 Enc(b2) + a2 Enc(b1) encrypts m1 m2 - b1 b2
        alpha = (
            self.cf.cs.encrypt(plaintext=(self.a * other.a) % modulo)
            + other.beta * self.a
            + self.beta * other.a
        )
        return CatalanoFioreCiphertext(cf=self.cf, alpha=alpha, pairs=[(self.beta, other.beta)])

    def __rmul__(self, other: int) -> "CatalanoFioreCiphertext":
        return self.__mul__(other)

    def to_multiplied(self) -> "CatalanoFioreCiphertext":
        """
        Represent a non-multiplied ciphertext (a, Enc(b)) as a multiplied one
            with alpha = Enc(a) + Enc(b) and no pairs
        """
        if self.is_multiplied:
            return self
        alpha = self.cf.cs.encrypt(plaintext=self.a) + self.beta
        return CatalanoFioreCiphertext(cf=self.cf, alpha=alpha, pairs=[])

    def __check_same_system(self, other: "CatalanoFioreCiphertext") -> None:
        if not isinstance(other, CatalanoFioreCiphertext):
            raise ValueError(
                "Catalano-Fiore ciphertexts can be added to a ciphertext or an integer, "
                f"but it is {type(other).__name__}"
            )
        if other.cf.plaintext_modulo != self.cf.plaintext_modulo:
            raise ValueError("Ciphertexts belong to different cryptosystems")
