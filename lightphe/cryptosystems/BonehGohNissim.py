# built-in dependencies
import random
import math
from typing import Optional, Tuple, Union

# third-party dependencies
from lightecc import LightECC
from lightecc.commons.errors import InvalidCurveOrder, PointNotOnCurve
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint
from lightecc.commons.pairing import _fp2_pow, _fp2_mul
import sympy
from sympy.ntheory.residue_ntheory import sqrt_mod

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/BonehGohNissim.py")


class BonehGohNissim(Homomorphic):
    """
    Boneh-Goh-Nissim algorithm is homomorphic with respect to the addition.
        It's also somehow homomorphic with respect to the multiplication
        only for one multiplication per ciphertext.
    Ref: https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/
    """

    def __init__(
        self,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
        max_tries: int = 10000,
    ):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): size of the keys to generate in bits. Default is 1024.
        """
        self.keys = keys or self.generate_keys(
            key_size=key_size or 1024,
            max_tries=max_tries,
        )

        self.ec = LightECC(
            form_name="weierstrass",
            curve_name="custom",
            config={
                "a": self.keys["public_key"]["curve"]["a"],
                "b": self.keys["public_key"]["curve"]["b"],
                "p": self.keys["public_key"]["curve"]["p"],
                "G": self.keys["public_key"]["curve"]["G"],
                "n": self.keys["public_key"]["curve"]["n"],
            },
        )

        if "private_key" in self.keys and "q2" in self.keys["private_key"]:
            self.plaintext_modulo = self.keys["private_key"]["q2"]
        else:
            self.plaintext_modulo = self.keys["public_key"]["curve"]["n"]
        self.ciphertext_modulo = self.ec.modulo

    def generate_keys(
        self,
        key_size: int,
        max_tries: int = 10000,
    ):
        """
        Generate public and private keys of Boneh-Goh-Nissim cryptosystem
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        for key_attempt in range(max_tries):
            # choose large odd distinct primes q1 and q2
            q1 = sympy.randprime(2 ** (key_size // 2), 2 ** (key_size // 2 + 1))
            q2 = sympy.randprime(2 ** (key_size // 2), 2 ** (key_size // 2 + 1))
            while q1 == q2:
                q2 = sympy.randprime(2 ** (key_size // 2), 2 ** (key_size // 2 + 1))

            n = q1 * q2

            # Find l such that p = n*l - 1 is prime and p ≡ 3 (mod 4).
            # Supersingularity of y² = x³ + x requires p ≡ 3 (mod 4).
            # Since n is odd (product of two odd primes), n*l ≡ 0 (mod 4)
            # iff l ≡ 0 (mod 4). So we iterate multiples of 4 systematically.
            l = None
            for l_candidate in range(4, max_tries * 4 + 4, 4):
                p_candidate = n * l_candidate - 1
                if sympy.isprime(p_candidate):
                    l = l_candidate
                    break

            if l is None:
                logger.debug(
                    f"No valid l found for attempt {key_attempt + 1}, retrying"
                )
                continue

            p = n * l - 1
            a = 1
            b = 0

            G = self.__find_generator(p, max_tries=max_tries)

            try:
                self.ec = LightECC(
                    form_name="weierstrass",
                    curve_name="custom",
                    config={"a": a, "b": b, "p": p, "G": G, "n": n},
                )
            except (InvalidCurveOrder, PointNotOnCurve):
                logger.debug(
                    f"Curve order validation failed for attempt {key_attempt + 1}, retrying"
                )
                continue

            logger.debug("Curve order validated by LightECC.")
            logger.debug(f"q1 = {q1}, q2 = {q2}, n = {n}, p = {p}, l = {l}")
            break
        else:
            raise Exception(f"Failed to generate keys after {max_tries} attempts")

        while True:
            r = random.randint(2, n - 1)
            if math.gcd(r, n) == 1:
                break

        u = r * self.ec.G
        h = u * q2

        keys["public_key"]["curve"] = {
            "a": a,
            "b": b,
            "p": p,
            "G": G,
            "n": n,
        }

        keys["private_key"]["q1"] = q1
        keys["private_key"]["q2"] = q2
        keys["public_key"]["G"] = G
        keys["public_key"]["u"] = u.get_point()
        keys["public_key"]["h"] = h.get_point()
        keys["public_key"]["l"] = l
        return keys

    @staticmethod
    def __find_generator(p, max_tries=10000) -> Tuple[int, int]:
        if not sympy.isprime(p):
            raise ValueError("p must be prime")

        for _ in range(max_tries):
            x = random.randint(0, p - 1)
            rhs = (pow(x, 3, p) + x) % p
            y_list = sqrt_mod(rhs, p, all_roots=True)  # get all square roots
            if y_list:  # if there is at least one solution
                return x, y_list[0]  # just return the first one

        raise Exception(f"Failed to find a generator after {max_tries} attempts")

    def _has_private_key(self) -> bool:
        return "private_key" in self.keys and "q2" in self.keys["private_key"]

    def generate_random_key(self) -> int:
        """
        Boneh-Goh-Nissim requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        if self._has_private_key():
            q2 = self.keys["private_key"]["q2"]
            return random.randint(1, q2 - 1)

        n = self.keys["public_key"]["curve"]["n"]
        logger.warn(
            "Private key is not available. Random key will be bounded by n"
            " instead of q2. Encryption will work for small plaintexts,"
            " but negative number encoding via plaintext_modulo will not"
            " round-trip correctly because plaintext_modulo is set to n"
            " (public) instead of q2 (private)."
        )
        return random.randint(1, n - 1)

    def encrypt(
        self, plaintext: int, random_key: Optional[int] = None
    ) -> EllipticCurvePoint:
        """
        Encrypt a given plaintext for optionally given random key with Boneh-Goh-Nissim
        Args:
            plaintext (int): message to encrypt
            random_key (int): one time random key for encryption
        Returns:
            ciphertext (EllipticCurvePoint): encrypted message as a point on the elliptic curve
        """
        r = random_key or self.generate_random_key()
        G = self.ec.G
        h = self.keys["public_key"]["h"]
        h = EllipticCurvePoint(x=h[0], y=h[1], curve=self.ec.curve)
        c = (G * plaintext) + (h * r)
        return c

    def decrypt(self, ciphertext: Union[EllipticCurvePoint, Tuple[int, int]]) -> int:
        """
        Decrypt a given ciphertext with Boneh-Goh-Nissim.
        Handles both G1 ciphertexts (EllipticCurvePoint, from encryption/addition)
        and G_T ciphertexts (tuple in F_{p^2}, from homomorphic multiplication).

        Args:
            ciphertext: encrypted message — either an EllipticCurvePoint or
                a tuple (a, b) representing a + b*i in F_{p^2}
        Returns:
            plaintext (int): restored message
        """
        q1 = self.keys["private_key"]["q1"]
        q2 = self.keys["private_key"]["q2"]

        if isinstance(ciphertext, tuple):
            return self._decrypt_gt(ciphertext, q1, q2)

        G = self.ec.G

        mP = ciphertext * q1
        P = G * q1

        # P has order q2, so DLP result is in [0, q2)
        if mP == self.ec.O:
            return 0

        for i in range(1, q2):
            iP = P * i
            if iP == mP:
                return i

        raise Exception("Decryption failed")

    def _decrypt_gt(self, ciphertext: tuple, q1: int, q2: int) -> int:
        """
        Decrypt a G_T ciphertext (result of homomorphic multiplication).

        e(C1, C2)^q1 = e(G, G)^(q1 * m1 * m2)
        Solve DLP: find m such that base^m == target, where
            base = e(G, G)^q1
            target = e(C1, C2)^q1

        Args:
            ciphertext: pairing value (a, b) in F_{p^2}
            q1: private key component
        Returns:
            plaintext product m1 * m2
        """
        p = self.ec.modulo
        G = self.ec.G

        # e(G, G) — pairing of generator with itself via distortion map
        e_gg = self.ec.pairing(G, G)

        # base = e(G, G)^q1, target = e(C1, C2)^q1
        base = _fp2_pow(e_gg, q1, p)
        target = _fp2_pow(ciphertext, q1, p)

        # brute-force DLP in G_T — result is in [0, q2)
        if target == (1, 0):
            return 0

        acc = (1, 0)
        for i in range(1, q2):
            acc = _fp2_mul(acc, base, p)
            if acc == target:
                return i

        raise Exception("Decryption of G_T ciphertext failed")

    def add(
        self,
        ciphertext1: Union[EllipticCurvePoint, Tuple[int, int]],
        ciphertext2: Union[EllipticCurvePoint, Tuple[int, int]],
    ) -> Union[EllipticCurvePoint, Tuple[int, int]]:
        """
        Add two ciphertexts with Boneh-Goh-Nissim
        Args:
            ciphertext1 (EllipticCurvePoint): first encrypted message as a point on the elliptic curve
            ciphertext2 (EllipticCurvePoint): second encrypted message as a point on the elliptic curve
        Returns:
            result (tuple): resulting ciphertext after addition
        """
        if isinstance(ciphertext1, EllipticCurvePoint) and isinstance(
            ciphertext2, EllipticCurvePoint
        ):
            return ciphertext1 + ciphertext2

        if isinstance(ciphertext1, tuple) and isinstance(ciphertext2, tuple):
            return _fp2_mul(ciphertext1, ciphertext2, self.ec.modulo)

        raise ValueError("Both ciphertexts must be of the same type for addition.")

    def multiply(
        self,
        ciphertext1: EllipticCurvePoint,
        ciphertext2: EllipticCurvePoint,
    ) -> Tuple[int, int]:
        """
        Homomorphic multiplication of two ciphertexts using the bilinear pairing.
        The result is an element of F_{p^2} (the pairing target group G_T),
        not a point on the elliptic curve. BGN supports only one multiplication
        per ciphertext — the result cannot be multiplied again.

        Args:
            ciphertext1: first encrypted message (point on E(F_p))
            ciphertext2: second encrypted message (point on E(F_p))
        Returns:
            result (tuple): pairing value (a, b) representing a + b*i in F_{p^2}
        """
        # The tuple (a, b) represents a + b·i where i² = -1 mod p
        if isinstance(ciphertext1, tuple) or isinstance(ciphertext2, tuple):
            raise ValueError(
                "Boneh-Goh-Nissim only supports multiplication ciphertexts once!"
            )
        result = self.ec.pairing(ciphertext1, ciphertext2)
        if not isinstance(result, tuple):
            raise ValueError(
                "Boneh-Goh-Nissim requires a supersingular curve with embedding degree 2. "
                "The pairing returned an F_p element instead of an F_{p^2} element."
            )

        # the pairing result is an element of F_{p²}, not a point on the curve.
        # In BGN, the pairing maps two curve points to a field element
        # (in the multiplicative group G_T). The result of e(C1, C2) lives
        # in F_{p²}*, not on the elliptic curve. The homomorphic multiplication
        # works in G_T (the target group of the pairing), not back on the curve.
        return result

    def multiply_by_constant(
        self, ciphertext: Union[EllipticCurvePoint, Tuple[int, int]], constant: int
    ) -> Union[EllipticCurvePoint, Tuple[int, int]]:
        """
        Multiply a ciphertext by a constant with Boneh-Goh-Nissim
        Args:
            ciphertext (tuple): encrypted message as a tuple of two points on the elliptic curve
            constant (int): constant to multiply with the ciphertext
        Returns:
            result (tuple): resulting ciphertext after multiplication
        """
        if isinstance(ciphertext, EllipticCurvePoint):
            return ciphertext * constant
        if isinstance(ciphertext, tuple):
            # For GT elements, we can use exponentiation to achieve scalar multiplication
            base = ciphertext
            result = (1, 0)  # identity element in F_{p^2}*
            for _ in range(constant):
                result = _fp2_mul(result, base, self.ec.modulo)
            return result

        raise ValueError(
            "Ciphertext must be either an EllipticCurvePoint or a tuple "
            "representing an F_{p^2} element for multiplication by constant."
        )

    def reencrypt(self, ciphertext: EllipticCurvePoint) -> EllipticCurvePoint:
        """
        Re-encrypt a given ciphertext with Boneh-Goh-Nissim
        Args:
            ciphertext (tuple): encrypted message as a tuple of two points on the elliptic curve
        Returns:
            reencrypted_ciphertext (tuple): re-encrypted message as a tuple of two points on the elliptic curve
        """
        h = self.keys["public_key"]["h"]
        h = EllipticCurvePoint(x=h[0], y=h[1], curve=self.ec.curve)
        r = self.generate_random_key()
        c_prime = ciphertext + (r * h)
        return c_prime
