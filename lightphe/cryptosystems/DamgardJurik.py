import random
import math
from typing import Optional
import sympy
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/DamgardJurik.py")


class DamgardJurik(Homomorphic):
    """
    Damgard-Jurik algorithm is a generalization of Paillier.
    It is homomorphic with respect to the addition.
    Ref: https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/
    """

    def __init__(self, s: int = 2, keys: Optional[dict] = None, key_size: Optional[int] = None):
        """
        Args:
            s (int): cryptosystem's module is going to be n^(s+1). if s == 1 then this is Paillier
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): key size in bits
        """
        self.keys = keys or self.generate_keys(key_size=key_size or 1024, s=s)
        n = self.keys["public_key"]["n"]
        self.plaintext_modulo = n
        self.ciphertext_modulo = pow(n, s + 1)

    def generate_keys(self, key_size: int, s: Optional[int] = None):
        """
        Generate public and private keys of Paillier cryptosystem
        Args:
            s (int): cryptosystem's module is going to be n^(s+1). if s == 1 then this is Paillier
            key_size (int): key size in bits
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        # picking a prime modulus p
        p = sympy.randprime(200, 2 ** int(key_size / 2) - 1)

        # picking a prime modulus q
        q = sympy.randprime(200, 2 ** int(key_size / 2) - 1)

        n = p * q
        phi = (p - 1) * (q - 1)
        g = 1 + n

        keys["private_key"]["phi"] = phi
        keys["public_key"]["g"] = g
        keys["public_key"]["n"] = n
        keys["public_key"]["s"] = s

        return keys

    def generate_random_key(self) -> int:
        """
        Paillier requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        n = self.keys["public_key"]["n"]
        while True:
            r = random.randint(0, n)
            if math.gcd(r, n) == 1:
                break
        return r

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> int:
        """
        Encrypt a given plaintext for optionally given random key with Paillier
        Args:
            plaintext (int): message to encrypt
            random_key (int): Paillier requires a random key that co-prime to n.
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (int): encrypted message
        """
        g = self.keys["public_key"]["g"]
        n = self.keys["public_key"]["n"]
        s = self.keys["public_key"]["s"]
        r = random_key or self.generate_random_key()
        modulo = pow(n, s + 1)

        # assert math.gcd(r, n) == 1
        c = (pow(g, plaintext, modulo) * pow(r, n, modulo)) % modulo
        # c = (pow(g, plaintext, modulo) * pow(r, pow(n, s), modulo)) % modulo
        if math.gcd(c, modulo) != 1:
            logger.info(f"WARNING! gcd({c=}, {modulo=}) != 1")
        return c

    def decrypt(self, ciphertext: int):
        """
        Decrypt a given ciphertext with Paillier
        Args:
            ciphertext (int): encrypted message
        Returns:
            plaintext (int): restored message
        """
        phi = self.keys["private_key"]["phi"]
        n = self.keys["public_key"]["n"]
        s = self.keys["public_key"]["s"]
        mu = pow(phi, -1, n)
        modulo = pow(n, s + 1)
        return (self.lx(pow(ciphertext, phi, modulo)) * mu) % (n)

    def add(self, ciphertext1: int, ciphertext2: int) -> int:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Encryption calculations are done in module n squared.
        Args:
            ciphertext1 (int): 1st ciphertext created with Paillier
            ciphertext2 (int): 2nd ciphertext created with Paillier
        Returns:
            ciphertext3 (int): 3rd ciphertext created with Paillier
        """
        n = self.keys["public_key"]["n"]
        s = self.keys["public_key"]["s"]
        modulo = pow(n, s + 1)
        return (ciphertext1 * ciphertext2) % modulo

    def multiply(self, ciphertext1: int, ciphertext2: int) -> int:
        raise ValueError("Damgard-Jurik is not homomorphic with respect to the multiplication")

    def xor(self, ciphertext1: int, ciphertext2: int) -> int:
        raise ValueError("Damgard-Jurik is not homomorphic with respect to the exclusive or")

    def multiply_by_contant(self, ciphertext: int, constant: int) -> int:
        """
        Multiply a ciphertext by a known plain constant
        Result of this must be equal to E(m1 * m2), where E(m1) = ciphertext
        Encryption calculations are done in module n squared.
        Args:
            ciphertext (int): ciphertext created with Damgard-Jurik
            constant (int): a known plain constant
        Returns:
            ciphertext (int): new ciphertext created with Damgard-Jurik
        """
        n = self.keys["public_key"]["n"]
        if constant > self.plaintext_modulo:
            constant = constant % self.plaintext_modulo
            logger.debug(
                f"Damgard-Jurik can encrypt messages [1, {n}]. "
                f"Seems constant exceeded this limit. New constant is {constant}"
            )
        return pow(ciphertext, constant, self.ciphertext_modulo)

    def reencrypt(self, ciphertext: int) -> int:
        """
        Re-generate ciphertext with re-encryption. Many ciphertext will be decrypted to same plaintext.
        Args:
            ciphertext (int): given ciphertext
        Returns:
            new ciphertext (int): different ciphertext for same plaintext
        """
        neutral_element = 0
        neutral_encrypted = self.encrypt(plaintext=neutral_element)
        return self.add(ciphertext1=ciphertext, ciphertext2=neutral_encrypted)

    def lx(self, x: int) -> int:
        """
        Find logarithm over cyclic group
        Args:
            x (int): some integer
        Returns:
            lx (int): (x-1) / n
        """
        n = self.keys["public_key"]["n"]
        y = (x - 1) // n
        assert y - int(y) == 0
        return int(y)
