# built-in dependencies
import random
import math
from typing import Optional, Tuple

# 3rd party dependencies
import sympy
from sympy import jacobi_symbol
from sympy.ntheory.residue_ntheory import sqrt_mod

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/CastagnosLaguillaumie.py")

# a binary quadratic form ax^2 + bxy + cy^2 is represented as (a, b, c)
Form = Tuple[int, int, int]


class CastagnosLaguillaumie(Homomorphic):
    """
    Castagnos-Laguillaumie algorithm is homomorphic with respect to the addition.
    Also, it supports power operation for ciphertext base and plaintext exponent.
    It is an ElGamal-like scheme in the class group of an imaginary quadratic order
    of discriminant Δp = -p^3 q, which has a subgroup F of order p with an easy
    discrete logarithm. So, decryption does not require brute force.
    Ref: Castagnos, G., Laguillaumie, F. (2015). Linearly Homomorphic Encryption from DDH.
        CT-RSA 2015. https://eprint.iacr.org/2015/047
    """

    REQUIRED_KEYS = {
        "public_key": ["p", "q", "g", "h"],
        "private_key": ["x"],
    }

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
            key_size (int): bit length of the fundamental discriminant Δk = -pq
            max_tries (int): maximum attempts to generate keys
        """
        self.keys = keys or self.generate_keys(
            key_size=key_size or 1024, max_tries=max_tries
        )
        p = self.keys["public_key"]["p"]
        q = self.keys["public_key"]["q"]

        self.delta_k = -p * q
        self.delta_p = p * p * self.delta_k
        self.bound = self.__find_bound(self.delta_k)

        self.plaintext_modulo = p
        self.ciphertext_modulo = abs(self.delta_p)

    def generate_keys(self, key_size: int, max_tries: int = 10000) -> dict:
        """
        Generate public and private keys of Castagnos-Laguillaumie cryptosystem
        Args:
            key_size (int): bit length of the fundamental discriminant Δk = -pq
            max_tries (int): maximum number of tries to generate keys
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        # p defines the message space Z_p. q must be greater than 4p to keep
        # the forms of the subgroup F reduced.
        p_size = max(4, key_size // 4)
        q_size = key_size - p_size

        for _ in range(max_tries):
            p = sympy.randprime(2 ** (p_size - 1), 2**p_size - 1)
            q = sympy.randprime(2 ** (q_size - 1), 2**q_size - 1)

            # pq = 3 mod 4 makes Δk = -pq a fundamental discriminant
            if (p * q) % 4 != 3 or jacobi_symbol(p, q) != -1:
                continue

            delta_k = -(p * q)
            delta_p = p * p * delta_k

            g = self.__find_generator(p=p, q=q, delta_k=delta_k, delta_p=delta_p)
            if g is not None:
                break
        else:
            raise Exception(f"Failed to generate keys after {max_tries} attempts")

        x = random.randint(1, self.__find_bound(delta_k))
        h = self.__pow(g, x, delta_p)

        keys["private_key"]["x"] = x
        keys["public_key"]["p"] = p
        keys["public_key"]["q"] = q
        keys["public_key"]["g"] = g
        keys["public_key"]["h"] = h

        return keys

    def __find_generator(
        self, p: int, q: int, delta_k: int, delta_p: int
    ) -> Optional[Form]:
        """
        Find g = [φp^-1(r^2)]^p where r is an ideal above a small split prime.
            Then g belongs to the subgroup of p-th powers in Cl(Δp)
        Args:
            p (int): prime defining the message space
            q (int): second prime of Δk
            delta_k (int): fundamental discriminant -pq
            delta_p (int): non-maximal order discriminant -p^3 q
        Returns:
            g (tuple): generator as a reduced binary quadratic form
        """
        for r in sympy.primerange(3, 10000):
            if r in (p, q) or jacobi_symbol(delta_k % r, r) != 1:
                continue

            # prime form above r in Cl(Δk). b must be odd and b^2 = Δk mod 4r
            b = sqrt_mod(delta_k % r, r)
            if b % 2 == 0:
                b = r - b
            r_form = (r, b, (b * b - delta_k) // (4 * r))

            # squaring prevents being in 2-torsion of the class group
            r2 = self.__compose(r_form, r_form, delta_k)
            if r2[0] % p == 0:
                continue

            # lift from Cl(Δk) to Cl(Δp) via φp^-1(a, b, c) = (a, bp, cp^2)
            lifted = self.__reduce((r2[0], r2[1] * p, r2[2] * p * p))
            g = self.__pow(lifted, p, delta_p)

            if g != self.__identity(delta_p):
                return g

        return None

    @staticmethod
    def __find_bound(delta_k: int) -> int:
        """
        Upper bound for exponents. Class number of Δk is about sqrt(|Δk|) log(|Δk|),
            and an additional 40 bits makes exponents statistically close to uniform.
        Args:
            delta_k (int): fundamental discriminant
        Returns:
            bound (int)
        """
        return math.isqrt(abs(delta_k)) * abs(delta_k).bit_length() * 2**40

    def generate_random_key(self) -> int:
        """
        Castagnos-Laguillaumie requires to generate one-time random key per encryption
        Returns:
            random key (int): one time random key for encryption
        """
        return random.randint(1, self.bound)

    def encrypt(
        self, plaintext: int, random_key: Optional[int] = None
    ) -> Tuple[Form, Form]:
        """
        Encrypt a given plaintext for optionally given random key with Castagnos-Laguillaumie
        Args:
            plaintext (int): message to encrypt in [0, p)
            random_key (int): one time random key for encryption
        Returns:
            ciphertext (tuple): pair of reduced binary quadratic forms (g^r, f^m h^r)
        """
        g = tuple(self.keys["public_key"]["g"])
        h = tuple(self.keys["public_key"]["h"])
        r = random_key or self.generate_random_key()

        c1 = self.__pow(g, r, self.delta_p)
        c2 = self.__compose(
            self.__f_pow(plaintext), self.__pow(h, r, self.delta_p), self.delta_p
        )
        return c1, c2

    def decrypt(self, ciphertext: Tuple[Form, Form]) -> int:
        """
        Decrypt a given ciphertext with Castagnos-Laguillaumie
        Args:
            ciphertext (tuple): pair of reduced binary quadratic forms
        Returns:
            plaintext (int): restored message
        """
        p = self.keys["public_key"]["p"]
        x = self.keys["private_key"]["x"]
        c1, c2 = tuple(ciphertext[0]), tuple(ciphertext[1])

        # f^m = c2 / c1^x
        c1_x = self.__pow(c1, x, self.delta_p)
        fm = self.__compose(c2, self.__inverse(c1_x), self.delta_p)

        if fm == self.__identity(self.delta_p):
            return 0

        # discrete logarithm in F is easy: f^m = (p^2, L(m) p, *)
        # where L(m) is congruent to m^-1 modulo p
        a, b, _ = fm
        if a != p * p or b % p != 0:
            raise ValueError("Decryption failed. Ciphertext does not belong to keys.")

        return pow(b // p, -1, p)

    def add(
        self, ciphertext1: Tuple[Form, Form], ciphertext2: Tuple[Form, Form]
    ) -> Tuple[Form, Form]:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Castagnos-Laguillaumie
            ciphertext2 (tuple): 2nd ciphertext created with Castagnos-Laguillaumie
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Castagnos-Laguillaumie
        """
        return (
            self.__compose(
                tuple(ciphertext1[0]), tuple(ciphertext2[0]), self.delta_p
            ),
            self.__compose(
                tuple(ciphertext1[1]), tuple(ciphertext2[1]), self.delta_p
            ),
        )

    def multiply_by_constant(
        self, ciphertext: Tuple[Form, Form], constant: int
    ) -> Tuple[Form, Form]:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * m2) where E(m1) = ciphertext
        Args:
            ciphertext (tuple): ciphertext created with Castagnos-Laguillaumie
            constant (int): known plain constant
        Returns:
            ciphertext (tuple): new ciphertext created with Castagnos-Laguillaumie
        """
        if constant >= self.plaintext_modulo:
            constant = constant % self.plaintext_modulo
            logger.debug(
                f"Castagnos-Laguillaumie can encrypt messages [0, {self.plaintext_modulo}). "
                f"Seems constant exceeded this limit. New constant is {constant}"
            )

        return (
            self.__pow(tuple(ciphertext[0]), constant, self.delta_p),
            self.__pow(tuple(ciphertext[1]), constant, self.delta_p),
        )

    def reencrypt(self, ciphertext: Tuple[Form, Form]) -> Tuple[Form, Form]:
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

    def __f_pow(self, m: int) -> Form:
        """
        Compute f^m in closed form where f = (p^2, p, *) generates the subgroup F of order p
        Args:
            m (int): exponent
        Returns:
            f^m (tuple): reduced binary quadratic form
        """
        p = self.keys["public_key"]["p"]
        m = m % p
        if m == 0:
            return self.__identity(self.delta_p)

        # L(m) is the odd integer in [-p, p] congruent to m^-1 modulo p
        l = pow(m, -1, p)
        if l % 2 == 0:
            l = l - p

        a = p * p
        b = l * p
        return self.__reduce((a, b, (b * b - self.delta_p) // (4 * a)))

    # binary quadratic form arithmetic
    # Ref: Cohen, H. (1993). A Course in Computational Algebraic Number Theory.

    @staticmethod
    def __identity(delta: int) -> Form:
        """
        Principal form of the class group for discriminant delta = 1 mod 4
        """
        return 1, 1, (1 - delta) // 4

    @staticmethod
    def __inverse(f: Form) -> Form:
        """
        Inverse of a reduced form in the class group
        """
        a, b, c = f
        return CastagnosLaguillaumie.__reduce((a, -b, c))

    @staticmethod
    def __normalize(f: Form) -> Form:
        """
        Find equivalent form with -a < b <= a
        """
        a, b, c = f
        r = (a - b) // (2 * a)
        return a, b + 2 * r * a, a * r * r + b * r + c

    @staticmethod
    def __reduce(f: Form) -> Form:
        """
        Find the unique reduced form equivalent to f, i.e. |b| <= a <= c,
            and b >= 0 if a = |b| or a = c (Cohen Algorithm 5.4.2)
        """
        a, b, c = f
        if not -a < b <= a:
            a, b, c = CastagnosLaguillaumie.__normalize((a, b, c))

        while a > c:
            a, b, c = CastagnosLaguillaumie.__normalize((c, -b, a))

        if a == c and b < 0:
            b = -b

        return a, b, c

    @staticmethod
    def __compose(f1: Form, f2: Form, delta: int) -> Form:
        """
        Composition of two forms with discriminant delta (Cohen Algorithm 5.4.7)
        """
        if f1[0] > f2[0]:
            f1, f2 = f2, f1
        a1, b1, _ = f1
        a2, b2, c2 = f2

        s = (b1 + b2) // 2
        n = b2 - s

        if a2 % a1 == 0:
            y1 = 0
            d = a1
        else:
            d, y1, _ = _xgcd(a2, a1)

        if s % d == 0:
            y2 = -1
            x2 = 0
            d1 = d
        else:
            d1, x2, v = _xgcd(s, d)
            y2 = -v

        v1 = a1 // d1
        v2 = a2 // d1
        r = (y1 * y2 * n - x2 * c2) % v1
        b3 = b2 + 2 * v2 * r
        a3 = v1 * v2
        c3 = (b3 * b3 - delta) // (4 * a3)
        return CastagnosLaguillaumie.__reduce((a3, b3, c3))

    @staticmethod
    def __pow(f: Form, exponent: int, delta: int) -> Form:
        """
        Exponentiation in the class group with square and multiply
        """
        result = CastagnosLaguillaumie.__identity(delta)
        base = f
        while exponent > 0:
            if exponent & 1:
                result = CastagnosLaguillaumie.__compose(result, base, delta)
            base = CastagnosLaguillaumie.__compose(base, base, delta)
            exponent >>= 1
        return result


def _xgcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended euclidean algorithm
    Returns:
        (d, u, v) such that u * a + v * b = d = gcd(a, b)
    """
    u0, u1, v0, v1 = 1, 0, 0, 1
    while b != 0:
        quotient = a // b
        a, b = b, a - quotient * b
        u0, u1 = u1, u0 - quotient * u1
        v0, v1 = v1, v0 - quotient * v1
    return a, u0, v0
