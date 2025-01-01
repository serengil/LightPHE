import random
import math
from typing import Optional
import sympy
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/RSA.py")


class RSA(Homomorphic):
    """
    RSA algorithm is partially homomorphic with respect to the multiplication
    Ref: https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/
    """

    def __init__(self, keys: Optional[dict] = None, key_size: Optional[int] = None, encrypt_with_public=True):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): key size in bits
            encrypt_with_public (boolean): RSA has two keys: private (d) and public (e).
                If you encrypt a message with smo's public, then just that person can decrypt it
                with his private (secure message). Otherwise, if you encrypt it with your private,
                one can decrypt it with your public (digital signatures).
                Set this arg to True if you want to do encryption with public key e,
                and do decryption with private key d.
        """
        self.keys = keys or self.generate_keys(key_size or 1024)
        self.plaintext_modulo = self.keys["public_key"]["n"]
        self.ciphertext_modulo = self.keys["public_key"]["n"]
        self.encrypt_with_public = encrypt_with_public

    def generate_keys(self, key_size: int) -> dict:
        """
        Generate public and private keys of RSA cryptosystem
        Args:
            key_size (int): key size in bits
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        while True:
            try:
                # picking a prime modulus p and q
                p = sympy.randprime(200, 2 ** int(key_size / 2) - 1)
                q = sympy.randprime(200, 2 ** int(key_size / 2) - 1)

                n = p * q
                phi = (p - 1) * (q - 1)

                # select public exponent e
                while True:
                    e = random.randint(1, phi - 1)
                    if math.gcd(e, n) == 1:
                        break

                d = pow(e, -1, phi)
                break
            except:
                pass

        keys["public_key"]["n"] = n
        keys["public_key"]["e"] = e
        keys["private_key"]["d"] = d
        return keys

    def generate_random_key(self) -> int:
        pass

    def encrypt(self, plaintext: int) -> int:
        """
        Encrypt plain messages with RSA
        Args:
            plaintext (int): plain message
        Returns:
            ciphertext (int): ciphertext encrypted with RSA
        """
        n = self.keys["public_key"]["n"]

        if plaintext > n:
            plaintext = plaintext % n
            logger.debug(
                f"RSA can encrypt messages [1, {n}]. "
                f"Seems you exceeded this limit. New plaintext is {plaintext}"
            )

        if self.encrypt_with_public is True:
            e = self.keys["public_key"]["e"]
            c = pow(plaintext, e, n)
        else:
            d = self.keys["private_key"]["d"]
            c = pow(plaintext, d, n)

        return c

    def decrypt(self, ciphertext: int) -> int:
        """
        Decrypt ciphertexts with RSA
        Args:
            ciphertext (int): encrypted message
            decrypt_with_private (int): RSA has two keys: private (d) and public (e).
                If you encrypt a message with smo's public, then just that person can decrypt it
                with his private (secure message). Otherwise, if you encrypt it with your private,
                one can decrypt it with your public (digital signatures).
                Set this arg to True if you want to do encryption with public key e,
                and do decryption with private key d.
        Returns:
            plaintext (int): restored message
        """
        n = self.keys["public_key"]["n"]
        if self.encrypt_with_public is True:
            d = self.keys["private_key"]["d"]
            p = pow(ciphertext, d, n)
        else:
            e = self.keys["public_key"]["e"]
            p = pow(ciphertext, e, n)

        return p

    def multiply(self, ciphertext1: int, ciphertext2: int) -> int:
        """
        Perform homomorphic multiplication on encrypted data.
        Result of this must be equal to E(m1 * m2)
        """
        n = self.keys["public_key"]["n"]
        return (ciphertext1 * ciphertext2) % n

    def add(self, ciphertext1: int, ciphertext2: int) -> int:
        raise ValueError("RSA is not homomorphic with respect to the addition")

    def xor(self, ciphertext1: int, ciphertext2: int) -> int:
        raise ValueError("RSA is not homomorphic with respect to the exclusive or")

    def multiply_by_contant(self, ciphertext: int, constant: int) -> int:
        raise ValueError("RSA is not supporting multiplying ciphertext by a known constant")

    def reencrypt(self, ciphertext: int) -> int:
        raise ValueError("RSA does not support re-encryption")
