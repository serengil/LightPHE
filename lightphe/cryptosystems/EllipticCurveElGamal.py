# built-in dependencies
import random
from typing import Any, Optional, List, Tuple

# 3rd party dependencies
from lightecc import LightECC as ECC
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger
from lightphe.commons import threshold as threshold_utils
from lightphe.commons import zkp

logger = Logger(module="lightphe/cryptosystems/EllipticCurveElGamal.py")

DECRYPTION_DOMAIN = "lightphe/elliptic-curve-elgamal/decryption"
PARTIAL_DECRYPTION_DOMAIN = "lightphe/elliptic-curve-elgamal/partial-decryption"
MEMBERSHIP_DOMAIN = "lightphe/elliptic-curve-elgamal/membership"
KNOWLEDGE_DOMAIN = "lightphe/elliptic-curve-elgamal/knowledge"


class EllipticCurveElGamal(Homomorphic):
    """
    Elliptic Curve ElGamal algorithm is an additively homomorphic algorithm
    Unluckily, it requires to solve (EC)DLP to restore plaintext in decryption
    However it is easy to restore plaintext while plaintext is not very large
    unsimilar to Benaloh or Naccache-Stern
    Ref: https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/
    """

    REQUIRED_KEYS = {
        "public_key": ["Qa"],
        "private_key": ["ka"],
    }

    def __init__(
        self,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
        form: Optional[str] = None,
        curve: Optional[str] = None,
    ):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): key size in bits. default is 160.
                this is equivalent to 1024 bit RSA.
            form (str): specifies the elliptic curve form.
                Options are 'weierstrass' (default), 'edwards'.
            curve (str): specifies the elliptic curve to use.
                Options:
                 - ed25519, ed448 for edwards form
                 - secp256k1 for weierstrass form
                This parameter is only used if `algorithm_name` is 'EllipticCurve-ElGamal'.
        """
        self.ecc = ECC(form_name=form, curve_name=curve)

        self.keys = keys or self.generate_keys(key_size or self.ecc.n.bit_length())

        if curve is not None:
            self.keys["curve"] = curve

        if form is not None:
            self.keys["form"] = form

        self.plaintext_modulo = self.ecc.modulo
        self.ciphertext_modulo = self.ecc.modulo

    def generate_keys(self, key_size: int):
        """
        Generate public and private keys of Elliptic Curve ElGamal cryptosystem
        Args:
            key_size (int): key size in bits
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        # private key
        ka = random.getrandbits(key_size)
        logger.debug(
            f"{key_size} bit private key generated for Elliptic Curve ElGamal."
        )

        # base point

        # public key
        Qa = self.ecc.G * ka

        keys["public_key"]["Qa"] = Qa.get_point()
        keys["private_key"]["ka"] = ka

        return keys

    def generate_random_key(self) -> int:
        """
        Elliptic Curve ElGamal requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        # return random.getrandbits(128)
        return random.getrandbits(self.ecc.n.bit_length())

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> tuple:
        """
        Encrypt plaintext with Elliptic Curve ElGamal
        Args:
            plaintext (int): message to encrypt
            random_key (int): random key for encryption. Do not set this to a static value.
        Returns
            ciphertext (tuple): c1 and c2
        """
        # public key
        x, y = self.keys["public_key"]["Qa"]
        Qa = EllipticCurvePoint(x=x, y=y, curve=self.ecc.curve)

        # random key
        r = random_key or self.generate_random_key()

        s = self.ecc.G * plaintext

        c1 = self.ecc.G * r
        c2 = (Qa * r) + s

        return c1.get_point(), c2.get_point()

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt ciphertext with Elliptic Curve ElGamal
        Args:
            ciphertext (tuple): c1 and c2
        Returns:
            plaintext (int): restored message
        """
        # private key
        ka = self.keys["private_key"]["ka"]

        # c1 and c2 as tuple of integers
        c1, c2 = ciphertext

        c1 = EllipticCurvePoint(x=c1[0], y=c1[1], curve=self.ecc.curve)
        c2 = EllipticCurvePoint(x=c2[0], y=c2[1], curve=self.ecc.curve)

        s_prime = (-c1 * ka) + c2

        # s_prime is a point on the elliptic curve
        # s_prime = k x G
        # we need to find k from known s_prime and G
        # this requires to solve ECDLP

        return s_prime / self.ecc.G

    def generate_threshold_keys(self, threshold: int, parties: int) -> List[dict]:
        """
        Split the private key into shares. Any threshold many shareholders can decrypt
            a ciphertext together, but fewer shareholders cannot. Verification keys
            share x G are published to verify partial decryptions.
        Args:
            threshold (int): minimum number of shareholders required to decrypt
            parties (int): total number of shareholders
        Returns:
            keys of shareholders (list of dict): public key and share of each shareholder
        """
        if parties >= self.ecc.n:
            raise ValueError(f"Number of parties must be less than the curve order {self.ecc.n}")
        shares = threshold_utils.split_secret(
            secret=self.keys["private_key"]["ka"],
            threshold=threshold,
            parties=parties,
            modulo=self.ecc.n,
        )
        return threshold_utils.build_share_keys(
            keys=self.keys,
            shares=shares,
            threshold=threshold,
            parties=parties,
            verification_keys=[
                (self.ecc.G * shares[index]).get_point() for index in range(1, parties + 1)
            ],
        )

    def partial_decrypt(self, ciphertext: tuple, prove: bool = False) -> dict:
        """
        Decrypt a ciphertext partially with the share of a shareholder, and optionally
            prove that it is computed with the share behind the verification key
        Args:
            ciphertext (tuple): c1 and c2
            prove (bool): set this to True to attach a zero-knowledge proof of
                correctness. Default is False. Combination with verify=True discards
                partial decryptions without proofs.
        Returns:
            partial decryption (dict): index of the shareholder, share x c1 and proof
        """
        threshold_key = threshold_utils.get_threshold_key(self.keys)
        index = threshold_key["index"]
        share = threshold_key["share"]
        c1 = self.__to_point(ciphertext[0])
        value = c1 * share
        if prove is False:
            return {"index": index, "value": value.get_point()}
        proof = zkp.prove_dleq(
            group=zkp.EllipticCurveGroup(self.ecc),
            g1=self.ecc.G,
            h1=self.ecc.G * share,
            g2=c1,
            h2=value,
            x=share,
            domain=PARTIAL_DECRYPTION_DOMAIN,
            context=[self.ecc.n, index],
        )
        return {"index": index, "value": value.get_point(), "proof": proof}

    def verify_partial_decryption(self, ciphertext: tuple, partial_decryption: dict) -> bool:
        """
        Verify that a partial decryption is computed with the share of its shareholder
        Args:
            ciphertext (tuple): c1 and c2
            partial_decryption (dict): output of partial_decrypt
        Returns:
            is valid (bool)
        """
        verification_keys = self.keys["public_key"].get("verification_keys")
        if verification_keys is None:
            raise ValueError("Public key does not have verification keys of shareholders")
        try:
            index = partial_decryption["index"]
            if not isinstance(index, int) or not 1 <= index <= len(verification_keys):
                return False
            return zkp.verify_dleq(
                group=zkp.EllipticCurveGroup(self.ecc),
                g1=self.ecc.G,
                h1=self.__to_point(verification_keys[index - 1]),
                g2=self.__to_point(ciphertext[0]),
                h2=self.__to_point(partial_decryption["value"]),
                proof=partial_decryption["proof"],
                domain=PARTIAL_DECRYPTION_DOMAIN,
                context=[self.ecc.n, index],
            )
        except Exception:  # pylint: disable=broad-except
            # malformed points raise errors of the elliptic curve library
            return False

    def combine_partial_decryptions(
        self, ciphertext: tuple, partial_decryptions: List[dict], verify: bool = False
    ) -> int:
        """
        Restore plaintext from partial decryptions of threshold many shareholders.
            If verify is True, partial decryptions with invalid or missing proofs are discarded.
        Args:
            ciphertext (tuple): c1 and c2
            partial_decryptions (list of dict): partial decryptions of shareholders
            verify (bool): set this to True to check proofs of partial decryptions.
                Default is False, then a wrong partial decryption of a cheating
                shareholder causes a wrong plaintext silently.
        Returns:
            plaintext (int): restored message
        """
        selected = threshold_utils.select_partial_decryptions(
            keys=self.keys,
            partial_decryptions=partial_decryptions,
            verify=(
                (
                    lambda partial_decryption: self.verify_partial_decryption(
                        ciphertext=ciphertext, partial_decryption=partial_decryption
                    )
                )
                if verify is True
                else None
            ),
        )
        indices = [partial_decryption["index"] for partial_decryption in selected]

        # ka x c1 restored with lagrange interpolation
        s_prime = self.__to_point(ciphertext[1])
        for partial_decryption in selected:
            coefficient = threshold_utils.lagrange_coefficient(
                index=partial_decryption["index"], indices=indices, modulo=self.ecc.n
            )
            point = self.__to_point(partial_decryption["value"])
            s_prime = (-point * coefficient) + s_prime

        # s_prime = m x G, solve ECDLP
        return s_prime / self.ecc.G

    def decrypt_with_proof(self, ciphertext: tuple) -> Tuple[int, dict]:
        """
        Decrypt a ciphertext and prove that decryption is correct without revealing
            the private key. Chaum-Pedersen proof shows that log_G(Qa) = log_c1(ka x c1).
        Args:
            ciphertext (tuple): c1 and c2
        Returns:
            plaintext (int): restored message
            proof (dict): proof of correct decryption
        """
        ka = self.keys["private_key"]["ka"]
        c1 = self.__to_point(ciphertext[0])
        c2 = self.__to_point(ciphertext[1])
        c1_ka = c1 * ka
        proof = zkp.prove_dleq(
            group=zkp.EllipticCurveGroup(self.ecc),
            g1=self.ecc.G,
            h1=self.__to_point(self.keys["public_key"]["Qa"]),
            g2=c1,
            h2=c1_ka,
            x=ka,
            domain=DECRYPTION_DOMAIN,
            context=[self.ecc.n, c2],
        )
        return (-c1_ka + c2) / self.ecc.G, proof

    def verify_decryption(self, ciphertext: tuple, plaintext: int, proof: dict) -> bool:
        """
        Verify that a ciphertext is decrypted to the given plaintext with public key only
        Args:
            ciphertext (tuple): c1 and c2
            plaintext (int): claimed plaintext, checked in modulo of the curve order
            proof (dict): output of decrypt_with_proof
        Returns:
            is valid (bool)
        """
        try:
            if not isinstance(plaintext, int):
                return False
            c1 = self.__to_point(ciphertext[0])
            c2 = self.__to_point(ciphertext[1])

            # ka x c1 implied by the claimed plaintext
            m = plaintext % self.ecc.n
            c1_ka = c2 if m == 0 else c2 - (self.ecc.G * m)

            return zkp.verify_dleq(
                group=zkp.EllipticCurveGroup(self.ecc),
                g1=self.ecc.G,
                h1=self.__to_point(self.keys["public_key"]["Qa"]),
                g2=c1,
                h2=c1_ka,
                proof=proof,
                domain=DECRYPTION_DOMAIN,
                context=[self.ecc.n, c2],
            )
        except Exception:  # pylint: disable=broad-except
            # malformed points raise errors of the elliptic curve library
            return False

    def encrypt_with_proof(
        self, plaintext: int, values: List[int], context: Any = None
    ) -> Tuple[tuple, dict]:
        """
        Encrypt a plaintext and prove that it is one of the given values without
            revealing which one, e.g. a vote is 0 or 1. Disjunctive Chaum-Pedersen proof
            shows that c2 - v x G is r x Qa for one of the values v.
        Args:
            plaintext (int): message to encrypt, must be one of values
            values (list of int): allowed values
            context (any): public data bound to the proof, e.g. id of the voter
        Returns:
            ciphertext (tuple): c1 and c2
            proof (dict): proof that ciphertext encrypts one of values
        """
        r = self.generate_random_key()
        ciphertext = self.encrypt(plaintext=plaintext, random_key=r)
        proof = self.prove_membership(
            ciphertext=ciphertext, plaintext=plaintext, random_key=r, values=values, context=context
        )
        return ciphertext, proof

    def prove_membership(
        self,
        ciphertext: tuple,
        plaintext: int,
        random_key: int,
        values: List[int],
        context: Any = None,
    ) -> dict:
        """
        Prove that a ciphertext encrypts one of the given values, without revealing which
            one. Encryptor of the ciphertext knows its plaintext and random key, e.g. a
            ciphertext restored homomorphically from ciphertexts encrypted by the prover.
        Args:
            ciphertext (tuple): encrypted message
            plaintext (int): message of the ciphertext, must be one of values
            random_key (int): random key of the ciphertext
            values (list of int): allowed values
            context (any): public data bound to the proof
        Returns:
            proof (dict): proof that ciphertext encrypts one of values
        """
        return zkp.prove_dleq_or(
            group=zkp.EllipticCurveGroup(self.ecc),
            g1=self.ecc.G,
            h1=self.__to_point(ciphertext[0]),
            g2=self.__to_point(self.keys["public_key"]["Qa"]),
            h2s=self.__membership_candidates(ciphertext=ciphertext, values=values),
            x=random_key,
            index=values.index(plaintext),
            domain=MEMBERSHIP_DOMAIN,
            context=[self.ecc.n, ciphertext[1], values, context],
        )

    def combine_random_keys(self, random_keys: List[int]) -> int:
        """
        Random key of the homomorphic sum of ciphertexts, as c1 = r x G adds
        Args:
            random_keys (list of int): random keys of ciphertexts
        Returns:
            random key (int): random key of the sum of ciphertexts
        """
        return sum(random_keys)

    def verify_ciphertext(
        self, ciphertext: tuple, proof: dict, values: List[int], context: Any = None
    ) -> bool:
        """
        Verify that a ciphertext encrypts one of the given values with public key only
        Args:
            ciphertext (tuple): c1 and c2
            proof (dict): output of encrypt_with_proof
            values (list of int): allowed values
            context (any): public data that the proof is expected to be bound to
        Returns:
            is valid (bool)
        """
        try:
            return zkp.verify_dleq_or(
                group=zkp.EllipticCurveGroup(self.ecc),
                g1=self.ecc.G,
                h1=self.__to_point(ciphertext[0]),
                g2=self.__to_point(self.keys["public_key"]["Qa"]),
                h2s=self.__membership_candidates(ciphertext=ciphertext, values=values),
                proof=proof,
                domain=MEMBERSHIP_DOMAIN,
                context=[self.ecc.n, ciphertext[1], values, context],
            )
        except Exception:  # pylint: disable=broad-except
            # malformed points raise errors of the elliptic curve library
            return False

    def __membership_candidates(
        self, ciphertext: tuple, values: List[int]
    ) -> List[EllipticCurvePoint]:
        """
        Candidates c2 - v x G for each value v. Ciphertext encrypts v if and only if
            its candidate is r x Qa where c1 = r x G.
        Args:
            ciphertext (tuple): c1 and c2
            values (list of int): allowed values
        Returns:
            candidates (list of EllipticCurvePoint)
        """
        c2 = self.__to_point(ciphertext[1])
        candidates = []
        for value in values:
            m = value % self.ecc.n
            candidates.append(c2 if m == 0 else c2 - (self.ecc.G * m))
        return candidates

    def encrypt_with_proof_of_knowledge(
        self, plaintext: int, context: Any = None
    ) -> Tuple[tuple, dict]:
        """
        Encrypt a plaintext and prove knowledge of it without revealing it. Schnorr
            proof shows knowledge of r where c1 = r x G, which reveals the plaintext from c2.
            It is bound to c2, so a copied, re-randomized or modified ciphertext of
            someone else cannot be proven.
        Args:
            plaintext (int): message to encrypt
            context (any): public data bound to the proof, e.g. id of the encryptor
        Returns:
            ciphertext (tuple): c1 and c2
            proof (dict): proof of knowledge
        """
        r = self.generate_random_key()
        ciphertext = self.encrypt(plaintext=plaintext, random_key=r)
        proof = zkp.prove_dlog(
            group=zkp.EllipticCurveGroup(self.ecc),
            g=self.ecc.G,
            h=self.__to_point(ciphertext[0]),
            x=r,
            domain=KNOWLEDGE_DOMAIN,
            context=[self.ecc.n, ciphertext[1], context],
        )
        return ciphertext, proof

    def verify_knowledge(self, ciphertext: tuple, proof: dict, context: Any = None) -> bool:
        """
        Verify that the encryptor of a ciphertext knows its plaintext with public key only
        Args:
            ciphertext (tuple): c1 and c2
            proof (dict): output of encrypt_with_proof_of_knowledge
            context (any): public data that the proof is expected to be bound to
        Returns:
            is valid (bool)
        """
        try:
            # c2 must be a point on the curve
            self.__to_point(ciphertext[1])
            return zkp.verify_dlog(
                group=zkp.EllipticCurveGroup(self.ecc),
                g=self.ecc.G,
                h=self.__to_point(ciphertext[0]),
                proof=proof,
                domain=KNOWLEDGE_DOMAIN,
                context=[self.ecc.n, ciphertext[1], context],
            )
        except Exception:  # pylint: disable=broad-except
            # malformed points raise errors of the elliptic curve library
            return False

    def __to_point(self, point: tuple) -> EllipticCurvePoint:
        """
        Cast a tuple of coordinates into a point on the curve
        Args:
            point (tuple): x and y
        Returns:
            point (EllipticCurvePoint)
        """
        return EllipticCurvePoint(x=point[0], y=point[1], curve=self.ecc.curve)

    def add(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic addition on encrypted data
        Result of this must be equal to E(m1 + m2)
        Args:
            ciphertext1 (dict): Elliptic Curve ElGamal ciphertext consisting of c1 and c2 keys
            ciphertext2 (dict): Elliptic Curve ElGamal ciphertext consisting of c1 and c2 keys
        Returns
            ciphertext (dict): Elliptic Curve ElGamal ciphertext consisting of c1 and c2 keys
        """
        c1_1, c1_2 = ciphertext1
        c2_1, c2_2 = ciphertext2

        # cast them to elliptic curve points
        c1_1 = EllipticCurvePoint(x=c1_1[0], y=c1_1[1], curve=self.ecc.curve)
        c1_2 = EllipticCurvePoint(x=c1_2[0], y=c1_2[1], curve=self.ecc.curve)
        c2_1 = EllipticCurvePoint(x=c2_1[0], y=c2_1[1], curve=self.ecc.curve)
        c2_2 = EllipticCurvePoint(x=c2_2[0], y=c2_2[1], curve=self.ecc.curve)

        a = c1_1 + c2_1
        b = c1_2 + c2_2

        return a.get_point(), b.get_point()

    def multiply_by_constant(self, ciphertext: tuple, constant: int) -> tuple:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to k x E(m1) = E(m1 * k)
        where E(m1) = ciphertext
        Args:
            ciphertext (int): ciphertext created with Elliptic Curve ElGamal
            constant (int): known plain constant
        Returns:
            ciphertext (int): new ciphertext created with Elliptic Curve ElGamal
        """
        # Both P and Q are tuples of integers
        P, Q = ciphertext

        # cast P and Q to EllipticCurvePoint
        P = EllipticCurvePoint(x=P[0], y=P[1], curve=self.ecc.curve)
        Q = EllipticCurvePoint(x=Q[0], y=Q[1], curve=self.ecc.curve)

        P_prime = P * constant
        Q_prime = Q * constant

        return P_prime.get_point(), Q_prime.get_point()

    def reencrypt(self, ciphertext: tuple) -> tuple:
        """
        Re-encrypt a ciphertext with a new random key
        Args:
            ciphertext (tuple): c1 and c2
        Returns:
            ciphertext (tuple): new c1 and c2
        """
        r_prime = self.generate_random_key()

        x, y = self.keys["public_key"]["Qa"]
        Qa = EllipticCurvePoint(x=x, y=y, curve=self.ecc.curve)

        # c1 and c2 as tuple of integers
        c1, c2 = ciphertext
        c1 = EllipticCurvePoint(x=c1[0], y=c1[1], curve=self.ecc.curve)
        c2 = EllipticCurvePoint(x=c2[0], y=c2[1], curve=self.ecc.curve)

        c1_prime = c1 + r_prime * self.ecc.G
        c2_prime = c2 + r_prime * Qa
        return c1_prime.get_point(), c2_prime.get_point()
