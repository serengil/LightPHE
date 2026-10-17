# built-in dependencies
import random
import math
from typing import Optional, List

# 3rd party dependencies
import sympy

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/EllipticCurvePaillier.py")

# extra bits of the random key, so that it is statistically uniform modulo the order of g
RANDOM_KEY_EXTRA_BITS = 128


class EllipticCurvePaillier(Homomorphic):
    """
    Elliptic Curve Paillier algorithm is homomorphic with respect to the addition.
    Also, it supports power operation for ciphertext base and plaintext exponent.
    It is the elliptic curve analogue of Paillier. Paillier works in the multiplicative
    group Z_{n^2}*, whereas this works in the group of points on an elliptic curve
    y^2 = x^3 + b over the ring Z_{n^2} where n = pq.

    Points reducing to the point at infinity modulo n form a subgroup of order n, in which
    discrete logarithm is easy, similar to 1 + n in Paillier. A ciphertext is
    m * (n : 1 : 0) + r * g, where g is a point whose order is a secret factor of the
    group order. Multiplying a ciphertext by that order clears r * g and leaves m.

    p and q are 2 mod 3, so the curve has p + 1 points modulo p and q + 1 points modulo q
    as in KMOV cryptosystem, and the group order is known by the private key owner only.
    Points are in projective coordinates as division is not always possible in Z_{n^2}.
    Additions use complete formulas, which work for all points including doubling and
    the point at infinity, as the order of g is odd and so it has no point of order 2.
    Ciphertexts are 3 times larger than Paillier's, and operations are slower.

    Note: point arithmetic is implemented here instead of LightECC. LightECC supports
    custom curves, but it works with affine (x, y) points and divides in its addition
    formulas, which suits curves over prime fields as in Boneh-Goh-Nissim. Z_{n^2} is not
    a field, and messages live in points reducing to the point at infinity modulo n,
    such as (mn : 1 : 0). Those points cannot be written as affine points, and reaching
    them requires dividing by multiples of n. So, decryption with LightECC fails with
    "base is not invertible" for every non-zero message, and all such points would
    collapse into its single point at infinity anyway. Projective coordinates with
    complete formulas never divide and keep those points distinct.
    Ref: Galbraith, S. D. (2002). Elliptic Curve Paillier Schemes.
        Journal of Cryptology, 15(2), 129-138.
    Ref: Renes, J., Costello, C., Batina, L. (2016). Complete Addition Formulas
        for Prime Order Elliptic Curves. EUROCRYPT 2016.
    """

    REQUIRED_KEYS = {
        "public_key": ["n", "b", "g"],
        "private_key": ["order"],
    }

    def __init__(self, keys: Optional[dict] = None, key_size: Optional[int] = None):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): key size in bits
        """
        self.keys = keys or self.generate_keys(key_size or 1024)
        # exported keys store points as lists
        self.keys["public_key"]["g"] = tuple(self.keys["public_key"]["g"])
        n = self.keys["public_key"]["n"]
        self.plaintext_modulo = n
        self.ciphertext_modulo = n * n
        self.__g_powers: Optional[List[tuple]] = None

    def generate_keys(self, key_size: int) -> dict:
        """
        Generate public and private keys of Elliptic Curve Paillier cryptosystem
        Args:
            key_size (int): key size in bits
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        if key_size < 16:
            raise ValueError(f"Key size {key_size} is too small for Elliptic Curve Paillier")

        while True:
            p = self.__find_prime(bits=key_size // 2)
            q = self.__find_prime(bits=key_size // 2)
            if p == q:
                continue
            n = p * q
            n_square = n * n

            # exponent of the group modulo n, and its odd part
            exponent = (p + 1) * (q + 1) // math.gcd(p + 1, q + 1)
            order = exponent
            while order % 2 == 0:
                order //= 2
            if math.gcd(order, n) != 1:
                continue

            # random point P, and the curve passing through it
            x, y = random.randrange(n_square), random.randrange(n_square)
            b = (y * y - x**3) % n_square
            if math.gcd(b, n) != 1:
                continue

            # g has odd order dividing the secret order
            g = self.__multiply((x, y, 1), n * (exponent // order), b, n_square)
            if math.gcd(g[2], n) != 1:
                continue
            z_inv = pow(g[2], -1, n_square)
            g = ((g[0] * z_inv) % n_square, (g[1] * z_inv) % n_square)
            break

        keys["public_key"]["n"] = n
        keys["public_key"]["b"] = b
        keys["public_key"]["g"] = g

        keys["private_key"]["order"] = order
        keys["private_key"]["p"] = p
        keys["private_key"]["q"] = q

        return keys

    def generate_random_key(self) -> int:
        """
        Elliptic Curve Paillier requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        n = self.keys["public_key"]["n"]
        return random.randint(1, n << RANDOM_KEY_EXTRA_BITS)

    def encrypt(self, plaintext: int, random_key: Optional[int] = None) -> tuple:
        """
        Encrypt a given plaintext for optionally given random key with Elliptic Curve Paillier
        Args:
            plaintext (int): message to encrypt in [0, n)
            random_key (int): Elliptic Curve Paillier requires a random key
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (tuple): projective point m * (n : 1 : 0) + r * g
        """
        n = self.keys["public_key"]["n"]
        b = self.keys["public_key"]["b"]
        r = random_key or self.generate_random_key()

        if plaintext >= n:
            plaintext = plaintext % n
            logger.debug(
                f"Elliptic Curve Paillier can encrypt messages [0, {n}). "
                f"Seems plaintext exceeded this limit. New plaintext is {plaintext}"
            )

        # m * (n : 1 : 0) = (mn : 1 : 0), similar to (1 + n)^m = 1 + mn in Paillier
        message_point = ((plaintext * n) % (n * n), 1, 0)
        return self.__add(message_point, self.__multiply_g(r), b, n * n)

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt a given ciphertext with Elliptic Curve Paillier
        Args:
            ciphertext (tuple): encrypted message
        Returns:
            plaintext (int): restored message
        """
        n = self.keys["public_key"]["n"]
        b = self.keys["public_key"]["b"]
        order = self.keys["private_key"]["order"]
        n_square = n * n

        # order * C = (order * m) * (n : 1 : 0) as order * r * g is the point at infinity
        x, y, z = self.__multiply(tuple(ciphertext), order, b, n_square)
        if x % n != 0 or z % n != 0 or math.gcd(y, n) != 1:
            raise ValueError("Ciphertext is invalid")

        # (kn : 1 : 0) -> k
        scaled_message = ((x * pow(y, -1, n_square)) % n_square) // n
        return (scaled_message * pow(order, -1, n)) % n

    def add(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Elliptic Curve Paillier
            ciphertext2 (tuple): 2nd ciphertext created with Elliptic Curve Paillier
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Elliptic Curve Paillier
        """
        n = self.keys["public_key"]["n"]
        b = self.keys["public_key"]["b"]
        return self.__add(tuple(ciphertext1), tuple(ciphertext2), b, n * n)

    def multiply_by_constant(self, ciphertext: tuple, constant: int) -> tuple:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * constant) where E(m1) = ciphertext
        Args:
            ciphertext (tuple): ciphertext created with Elliptic Curve Paillier
            constant (int): known plain constant
        Returns:
            ciphertext (tuple): new ciphertext created with Elliptic Curve Paillier
        """
        n = self.keys["public_key"]["n"]
        b = self.keys["public_key"]["b"]

        if constant >= self.plaintext_modulo:
            constant = constant % self.plaintext_modulo
            logger.debug(
                f"Elliptic Curve Paillier can encrypt messages [0, {n}). "
                f"Seems constant exceeded this limit. New constant is {constant}"
            )

        return self.__multiply(tuple(ciphertext), constant, b, n * n)

    def reencrypt(self, ciphertext: tuple) -> tuple:
        """
        Re-generate ciphertext with re-encryption. Many ciphertext will be decrypted to same plaintext.
        Args:
            ciphertext (tuple): given ciphertext
        Returns:
            new ciphertext (tuple): different ciphertext for same plaintext
        """
        neutral_element = 0
        neutral_encrypted = self.encrypt(plaintext=neutral_element)
        return self.add(ciphertext1=ciphertext, ciphertext2=neutral_encrypted)

    @staticmethod
    def __add(point1: tuple, point2: tuple, b: int, mod: int) -> tuple:
        """
        Add two projective points on y^2 = x^3 + b over Z_{n^2} with complete formulas
            (Algorithm 7 of Renes-Costello-Batina for a = 0)
        Args:
            point1 (tuple): (X1 : Y1 : Z1)
            point2 (tuple): (X2 : Y2 : Z2)
            b (int): curve coefficient
            mod (int): n^2
        Returns:
            sum (tuple): (X3 : Y3 : Z3)
        """
        b3 = 3 * b
        x1, y1, z1 = point1
        x2, y2, z2 = point2

        t0 = (x1 * x2) % mod
        t1 = (y1 * y2) % mod
        t2 = (z1 * z2) % mod
        t3 = ((x1 + y1) * (x2 + y2) - t0 - t1) % mod
        t4 = ((y1 + z1) * (y2 + z2) - t1 - t2) % mod
        y3 = ((x1 + z1) * (x2 + z2) - t0 - t2) % mod
        t0 = (3 * t0) % mod
        t2 = (b3 * t2) % mod
        z3 = (t1 + t2) % mod
        t1 = (t1 - t2) % mod
        y3 = (b3 * y3) % mod
        x3 = (t3 * t1 - t4 * y3) % mod
        y3 = (t1 * z3 + y3 * t0) % mod
        z3 = (z3 * t4 + t0 * t3) % mod
        return x3, y3, z3

    @staticmethod
    def __multiply(point: tuple, scalar: int, b: int, mod: int) -> tuple:
        """
        Multiply a projective point with a scalar with double and add method
        Args:
            point (tuple): (X : Y : Z)
            scalar (int): non-negative integer
            b (int): curve coefficient
            mod (int): n^2
        Returns:
            scalar * point (tuple)
        """
        add = EllipticCurvePaillier.__add
        result = (0, 1, 0)
        for bit in bin(scalar)[2:]:
            result = add(result, result, b, mod)
            if bit == "1":
                result = add(result, point, b, mod)
        return result

    def __multiply_g(self, scalar: int) -> tuple:
        """
        Multiply g with a scalar using precomputed 2^i * g points, which avoids doublings
        Args:
            scalar (int): non-negative integer
        Returns:
            scalar * g (tuple)
        """
        n = self.keys["public_key"]["n"]
        b = self.keys["public_key"]["b"]
        n_square = n * n

        bits = max(scalar.bit_length(), (n << RANDOM_KEY_EXTRA_BITS).bit_length())
        if self.__g_powers is None or len(self.__g_powers) < bits:
            x, y = self.keys["public_key"]["g"]
            powers = [(x, y, 1)]
            for _ in range(bits - 1):
                powers.append(self.__add(powers[-1], powers[-1], b, n_square))
            self.__g_powers = powers

        result = (0, 1, 0)
        for i in range(scalar.bit_length()):
            if (scalar >> i) & 1:
                result = self.__add(result, self.__g_powers[i], b, n_square)
        return result

    @staticmethod
    def __find_prime(bits: int) -> int:
        """
        Find a prime p = 2 mod 3, so that y^2 = x^3 + b has p + 1 points modulo p
        Args:
            bits (int): bit length of p
        Returns:
            p (int): prime
        """
        while True:
            candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if candidate % 3 == 2 and sympy.isprime(candidate):
                return candidate
