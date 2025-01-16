import random
from typing import Optional
from lightphe.models.Homomorphic import Homomorphic
from lightphe.elliptic_curve_forms.weierstrass import Weierstrass
from lightphe.elliptic_curve_forms.edwards import TwistedEdwards
from lightphe.elliptic_curve_forms.koblitz import Koblitz
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/EllipticCurveElGamal.py")


class EllipticCurveElGamal(Homomorphic):
    """
    Elliptic Curve ElGamal algorithm is an additively homomorphic algorithm
    Unluckily, it requires to solve (EC)DLP to restore plaintext in decryption
    However it is easy to restore plaintext while plaintext is not very large
    unsimilar to Benaloh or Naccache-Stern
    Ref: https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/
    """

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
        if form is None or form == "weierstrass":
            self.curve = Weierstrass(curve=curve)
        elif form in "edwards":
            self.curve = TwistedEdwards(curve=curve)
        elif form in "koblitz":
            self.curve = Koblitz(curve=curve)
        else:
            raise ValueError(f"unimplemented curve form - {form}")

        self.keys = keys or self.generate_keys(key_size or self.curve.n.bit_length())
        self.keys["public_key"]["form"] = form
        self.keys["private_key"]["form"] = form
        self.plaintext_modulo = self.curve.modulo
        self.ciphertext_modulo = self.curve.modulo

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

        # public key
        Qa = self.curve.double_and_add(G=self.curve.G, k=ka)

        keys["public_key"]["Qa"] = Qa
        keys["private_key"]["ka"] = ka

        return keys

    def generate_random_key(self) -> int:
        """
        Elliptic Curve ElGamal requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        # return random.getrandbits(128)
        return random.getrandbits(
            (isinstance(self.curve.n, int) and self.curve.n.bit_length())
            or (isinstance(self.curve.n, str) and len(self.curve.n))
        )

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> tuple:
        """
        Encrypt plaintext with Elliptic Curve ElGamal
        Args:
            plaintext (int): message to encrypt
            random_key (int): random key for encryption. Do not set this to a static value.
        Returns
            ciphertext (tuple): c1 and c2
        """
        # base point
        G = self.curve.G

        # public key
        Qa = self.keys["public_key"]["Qa"]

        # random key
        r = random_key or self.generate_random_key()

        s = self.curve.double_and_add(G=G, k=plaintext)

        c1 = self.curve.double_and_add(G=G, k=r)

        c2 = self.curve.double_and_add(G=Qa, k=r)
        c2 = self.curve.add_points(c2, s)

        return c1, c2

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

        c1, c2 = ciphertext

        c1_prime = self.curve.negative_point(c1)
        s_prime = self.curve.double_and_add(G=c1_prime, k=ka)
        s_prime = self.curve.add_points(P=c2, Q=s_prime)

        # s_prime is a point on the elliptic curve
        # s_prime = k x G
        # we need to find k from known s_prime and G
        # this requires to solve ECDLP

        # base point
        G = self.curve.G
        k = 2
        while True:
            G = self.curve.add_points(P=G, Q=self.curve.G)
            if G[0] == s_prime[0] and G[1] == s_prime[1]:
                return k
            k = k + 1
            if k > self.curve.n:
                raise ValueError(
                    f"Cannot restore scalar from {s_prime} = k x {self.curve.G}"
                )

    def multiply(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        raise ValueError(
            "Elliptic Curve ElGamal is not homomorphic with respect to the multiplication"
        )

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
        a = self.curve.add_points(P=ciphertext1[0], Q=ciphertext2[0])
        b = self.curve.add_points(P=ciphertext1[1], Q=ciphertext2[1])
        return a, b

    def xor(self, ciphertext1: tuple, ciphertext2: tuple) -> int:
        raise ValueError(
            "Elliptic Curve ElGamal is not homomorphic with respect to the exclusive or"
        )

    def multiply_by_contant(self, ciphertext: tuple, constant: int) -> tuple:
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
        return self.curve.double_and_add(
            G=ciphertext[0],
            k=constant,
        ), self.curve.double_and_add(G=ciphertext[1], k=constant)

    def reencrypt(self, ciphertext: tuple) -> tuple:
        raise ValueError(
            "Elliptic Curve ElGamal does not support regeneration of ciphertext"
        )
