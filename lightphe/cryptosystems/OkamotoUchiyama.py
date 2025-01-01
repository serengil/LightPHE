import random
import math
from typing import Optional
import sympy
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/OkamotoUchiyama.py")


class OkamotoUchiyama(Homomorphic):
    """
    Okamoto-Uchiyama algorithm is homomorphic with respect to the addition.
    Ref: https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-okamoto-uchiyama-in-python/
    """

    def __init__(self, keys: Optional[dict] = None, key_size: Optional[int] = None):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): key size in bits
        """
        self.keys = keys or self.generate_keys(key_size or 1024)
        self.plaintext_modulo = self.keys["private_key"]["p"]
        self.ciphertext_modulo = self.keys["public_key"]["n"]

    def generate_keys(self, key_size: int) -> dict:
        """
        Generate public and private keys of OkamotoUchiyama cryptosystem
        Args:
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

        # modulo
        n = p * p * q

        # generator
        g = random.randint(2, n)

        if pow(g, p - 1, p * p) == 1:
            raise ValueError("Fermat's Little Theorem must be satisfied")

        h = pow(g, n, n)

        keys["public_key"]["n"] = n
        keys["public_key"]["g"] = g
        keys["public_key"]["h"] = h
        keys["private_key"]["p"] = p
        keys["private_key"]["q"] = q

        return keys

    def generate_random_key(self) -> int:
        """
        Okamoto-Uchiyama requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        n = self.keys["public_key"]["n"]
        return random.randint(1, n - 1)

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> int:
        """
        Encrypt a given plaintext for optionally given random key with OkamotoUchiyama
        Args:
            plaintext (int): message to encrypt
            random_key (int): OkamotoUchiyama requires a random key
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (int): encrypted message
        """

        g = self.keys["public_key"]["g"]
        n = self.keys["public_key"]["n"]
        h = self.keys["public_key"]["h"]
        r = random_key or self.generate_random_key()

        # having private key is not a must to encrypt but still if you have
        if self.keys.get("private_key") is not None:
            p = self.keys["private_key"]["p"]
            if plaintext > p:
                plaintext = plaintext % p
                logger.debug(
                    f"plaintext must be in scale [0, {p=}] but this is exceeded."
                    "New plaintext is {plaintext}"
                )
        return (pow(g, plaintext, n) * pow(h, r, n)) % n

    def decrypt(self, ciphertext: int):
        """
        Decrypt a given ciphertext with Okamoto-Uchiyama
        Args:
            ciphertext (int): encrypted message
        Returns:
            plaintext (int): restored message
        """
        p = self.keys["private_key"]["p"]
        g = self.keys["public_key"]["g"]

        a = self.lx(pow(ciphertext, p - 1, p * p))
        b = self.lx(pow(g, p - 1, p * p))
        return (a * pow(b, -1, p)) % p

    def add(self, ciphertext1: int, ciphertext2: int) -> int:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Encryption calculations are done in module n
        Args:
            ciphertext1 (int): 1st ciphertext created with OkamotoUchiyama
            ciphertext2 (int): 2nd ciphertext created with OkamotoUchiyama
        Returns:
            ciphertext3 (int): 3rd ciphertext created with OkamotoUchiyama
        """
        n = self.keys["public_key"]["n"]
        return (ciphertext1 * ciphertext2) % n

    def multiply(self, ciphertext1: int, ciphertext2: int) -> int:
        raise ValueError("Okamoto-Uchiyama is not homomorphic with respect to the multiplication")

    def xor(self, ciphertext1: int, ciphertext2: int) -> int:
        raise ValueError("Okamoto-Uchiyama is not homomorphic with respect to the exclusive or")

    def multiply_by_contant(self, ciphertext: int, constant: int) -> int:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * constant) where E(m1) = ciphertext
        Encryption calculations are done in module n squared.
        Args:
            ciphertext (int): ciphertext created with Okamoto-Uchiyama
            constant (int): known plain constant
        Returns:
            ciphertext (int): new ciphertext created with Okamoto-Uchiyama
        """
        n = self.keys["public_key"]["n"]
        if constant > self.plaintext_modulo:
            constant = constant % self.plaintext_modulo
            logger.debug(
                f"Okamoto-Uchiyama can encrypt messages [1, {n}]. "
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

    def lx(self, x: int) -> int:
        """
        Find logarithm over cyclic group
        Args:
            x (int): some integer
        Returns:
            lx (int): (x-1) / p
        """
        p = self.keys["private_key"]["p"]
        if x % p != 1:
            raise ValueError(f"Input passed to lx ({x}) must be identical to 1 in modulo {p}")
        if math.gcd(x, p * p) != 1:
            raise ValueError(f"gcd({x}, {p}^2) must be equal to 1")
        y = (x - 1) // p
        assert y - int(y) == 0
        return int(y)
