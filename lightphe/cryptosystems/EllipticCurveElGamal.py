# built-in dependencies
import random
from typing import Optional

# 3rd party dependencies
from lightecc import LightECC as ECC
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
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
