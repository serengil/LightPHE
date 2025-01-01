import random
from math import gcd
from typing import Optional
import sympy
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/Benaloh.py")


class Benaloh(Homomorphic):
    def __init__(self, keys: Optional[dict] = None, key_size: Optional[int] = None):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): key size in bits. default is less than other cryptosystems
                because decryption of Benaloh requires to solve DLP :/
        """
        self.keys = keys or self.generate_keys(key_size)
        self.plaintext_modulo = self.keys["public_key"]["r"]
        self.ciphertext_modulo = self.keys["public_key"]["n"]

    def generate_keys(self, key_size: int) -> dict:
        """
        Generate public and private keys of Paillier cryptosystem
        Args:
            key_size (int): key size in bits
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        x = 1
        while x == 1:
            # picking a prime p
            p = sympy.randprime(200, 2**(key_size or 50))
            # benaloh requires to solve DLP in decryption, so small key is recommended

            # picking a prime q
            q = sympy.randprime(100, p)

            n = p * q
            phi = (p - 1) * (q - 1)

            r = p - 1
            while gcd(q - 1, r) != 1:
                r = int(r / gcd(q - 1, r))

            if not (
                # r should divide p-1 without remainder
                (p - 1) % r == 0
                # r and (p - 1) / r must be coprimes
                and gcd(r, int((p - 1) / r)) == 1
                # r and q-1 must be coprimes
                and gcd(r, q - 1) == 1
            ):
                continue

            y = random.randint(2, n)
            if gcd(y, n) != 1:
                continue

            # to guarantee correct decryption
            prime_factors = sympy.factorint(r).keys()
            decryption_guaranteed = True
            for prime_factor in prime_factors:
                # none of r's prime factor should satisfy the condition
                if pow(y, int(phi / prime_factor), n) == 1:
                    decryption_guaranteed = False

            if decryption_guaranteed is False:
                continue

            x = pow(y, int(phi / r), n)
            if x != 1:
                break

        keys["public_key"]["y"] = y
        keys["public_key"]["r"] = r
        keys["public_key"]["n"] = n

        keys["private_key"]["p"] = p
        keys["private_key"]["q"] = q
        keys["private_key"]["phi"] = phi
        keys["private_key"]["x"] = x

        return keys

    def generate_random_key(self) -> int:
        """
        Generate random key for encryption
        """
        n = self.keys["public_key"]["n"]
        while True:
            u = random.randint(1, n)
            if gcd(u, n) == 1:
                break
        return u

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> int:
        """
        Encrypt a given plaintext for optionally given random key with Benaloh
        Args:
            plaintext (int): message to encrypt
            random_key (int): Benaloh requires a random key
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (int): encrypted message
        """
        y = self.keys["public_key"]["y"]
        r = self.keys["public_key"]["r"]
        n = self.keys["public_key"]["n"]

        u = random_key or self.generate_random_key()

        if plaintext > r:
            plaintext = plaintext % r
            logger.debug(
                f"Benaloh lets you to encrypt messages in [0, {r=}]."
                f"But your plaintext exceeds this limit."
                f"New plaintext is {plaintext}"
            )

        c = (pow(y, plaintext, n) * pow(u, r, n)) % n

        if gcd(c, n) != 1:
            logger.debug("ciphertext is not co-prime with n!")

        return c

    def decrypt(self, ciphertext: int) -> int:
        """
        Decrypt a given ciphertext with Benaloh
        Args:
            ciphertext (int): encrypted message
        Returns:
            plaintext (int): restored message
        """
        n = self.keys["public_key"]["n"]
        r = self.keys["public_key"]["r"]
        phi = self.keys["private_key"]["phi"]
        x = self.keys["private_key"]["x"]

        a = pow(ciphertext, int(phi / r), n)

        md = 0
        while True:
            if pow(x, md, n) == a:
                break
            md = md + 1
            if md > r:
                raise ValueError(f"Message cannot be restored in [{0}, {n}]")
        return md

    def add(self, ciphertext1: int, ciphertext2: int) -> int:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Encryption calculations are done in module n
        Args:
            ciphertext1 (int): 1st ciphertext created with Benaloh
            ciphertext2 (int): 2nd ciphertext created with Benaloh
        Returns:
            ciphertext3 (int): 3rd ciphertext created with Benaloh
        """
        n = self.keys["public_key"]["n"]
        return (ciphertext1 * ciphertext2) % n

    def multiply(self, ciphertext1: int, ciphertext2: int) -> int:
        raise ValueError("Benaloh is not homomorphic with respect to the multiplication")

    def xor(self, ciphertext1: int, ciphertext2: int) -> int:
        raise ValueError("Benaloh is not homomorphic with respect to the exclusive or")

    def multiply_by_contant(self, ciphertext: int, constant: int) -> int:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * constant) where E(m1) = ciphertext
        Encryption calculations are done in module n squared.
        Args:
            ciphertext (int): ciphertext created with Benaloh
            constant (int): known plain constant
        Returns:
            ciphertext (int): new ciphertext created with Benaloh
        """
        # raise ValueError("Benaloh is not supporting multiplying by a constant")
        n = self.keys["public_key"]["n"]
        if constant > self.plaintext_modulo:
            constant = constant % self.plaintext_modulo
            logger.debug(
                f"Benaloh can encrypt messages [1, {self.plaintext_modulo}]. "
                f"Seems constant exceeded this limit. New constant is {constant}"
            )
        return pow(ciphertext, constant, n)

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
