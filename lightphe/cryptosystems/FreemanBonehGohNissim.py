# built-in dependencies
import math
import secrets
from typing import Optional, List, Tuple, Dict

# 3rd party dependencies
import sympy
from sympy.ntheory.residue_ntheory import sqrt_mod
from lightecc import LightECC
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint
from lightecc.commons.pairing import _fp2_pow, _fp2_mul, _fp2_inv

# project dependencies
from lightphe.models.Homomorphic import Homomorphic
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/cryptosystems/FreemanBonehGohNissim.py")

# floats are scaled by powers of 10, which exceeds the range of discrete logarithm
FLOAT_NOT_SUPPORTED_MSG = (
    "Freeman-Boneh-Goh-Nissim does not support float values or tensors, because they are"
    " scaled by powers of 10, which exceed the range that decryption can restore."
    " Use integers instead."
)

# decrypted values must be in [-limit, limit] by default, as decryption solves
# discrete logarithm with baby-step giant-step
DEFAULT_PLAINTEXT_LIMIT = 2**20

# bit length of the prime group order r
MAX_ORDER_BITS = 256

# a ciphertext is a vector of DIMENSION points, and a multiplied one is DIMENSION^2 elements
DIMENSION = 3

# identity of the target group G_T in F_{p^2}
GT_ONE = (1, 0)


class FreemanBonehGohNissim(Homomorphic):
    """
    Freeman-Boneh-Goh-Nissim algorithm is the prime-order version of Boneh-Goh-Nissim.
    It is homomorphic with respect to the addition, and supports one multiplication of
    ciphertexts. Boneh-Goh-Nissim works in a group of composite order n = q1 q2, and its
    security relies on hardness of factoring n, which requires a large group. This works
    in a group of prime order r, and its security relies on decision linear assumption.

    Groups are vectors of 3 points on the supersingular curve y^2 = x^3 + x over F_p,
    whose points of order r have a symmetric pairing into F_{p^2}.
        - private key: secret vector v in Z_r^3
        - public key: h1 and h2 spanning the subgroup H of vectors orthogonal to v,
            and g out of H. Vectors are multiplied with the generator point P.
        - encryption: C = m g + a1 h1 + a2 h2 for random a1 and a2
        - decryption: projection pi(C) = v1 C1 + v2 C2 + v3 C3 = m pi(g) as pi(H) = 0,
            then discrete logarithm of it with base pi(g)
        - multiplication: 3 x 3 pairings e(C_i, C'_j). Its projection, product of
            e(C_i, C'_j)^(v_i v_j), is e(pi(C), pi(C')) = e(pi(g), pi(g))^(m m').
    Freeman's symmetric instantiation needs vectors of 3 points, because decisional
    Diffie-Hellman is easy in groups having a symmetric pairing.

    Notice that decryption solves discrete logarithm as in Boneh-Goh-Nissim, so decrypted
    values must be small: in [-limit, limit] where limit is 2^20 by default, and can be set
    with plaintext_limit. Floats and tensors are not supported. Ciphertexts are 3 points,
    and multiplied ciphertexts are 9 elements of F_{p^2}. Multiplied ciphertexts can be
    added with each other and multiplied with constants. Adding a fresh ciphertext to a
    multiplied one pairs it with g first, which costs 9 pairings.

    key_size is the bit length of the field size p. Default is 1024. The group order r is
    256 bits, and security is bounded by discrete logarithm in F_{p^2}: about 112 bits for
    p of 1024 bits, and 128 bits for p of 1536 bits. Boneh-Goh-Nissim of the same key size
    has about 80-bit security, as factoring its 1024-bit n is easier, and it needs a 2048-bit
    n to reach a similar level. Key generation takes about a second here, whereas it takes
    tens of seconds for Boneh-Goh-Nissim with 1024-bit keys, and much longer with 2048-bit
    keys. Encryption costs about the same as Boneh-Goh-Nissim with 1024-bit keys, but
    a multiplication costs 9 pairings instead of 1. Each pairing is cheaper, as the group
    order is 256 bits instead of the size of n. It is not quantum resistant.

    Ref: Freeman, D. M. (2010). Converting Pairing-Based Cryptosystems from Composite-Order
        Groups to Prime-Order Groups. EUROCRYPT 2010.
    Ref: Boneh, D., Goh, E.-J., Nissim, K. (2005). Evaluating 2-DNF Formulas on Ciphertexts.
        TCC 2005.
    """

    REQUIRED_KEYS = {
        "public_key": ["p", "r", "P", "g", "h1", "h2", "limit"],
        "private_key": ["v"],
    }

    def __init__(
        self,
        keys: Optional[dict] = None,
        key_size: Optional[int] = None,
        plaintext_limit: Optional[int] = None,
    ):
        """
        Args:
            keys (dict): private - public key pair.
                set this to None if you want to generate random keys.
            key_size (int): bit length of the field size p. Default is 1024.
            plaintext_limit (int): decrypted values must be in [-limit, limit].
                Default is 2^20. Decryption takes about sqrt(limit) steps.
        """
        self.keys = keys or self.generate_keys(
            key_size=key_size or 1024, plaintext_limit=plaintext_limit
        )
        public_key = self.keys["public_key"]
        self.ec = self.__build_curve(p=public_key["p"], r=public_key["r"], point=public_key["P"])
        self.plaintext_modulo = public_key["r"]
        self.ciphertext_modulo = public_key["p"]
        # baby-step giant-step tables, built when needed
        self.__tables: Dict[str, tuple] = {}

    def generate_keys(self, key_size: int, plaintext_limit: Optional[int] = None) -> dict:
        """
        Generate public and private keys of Freeman-Boneh-Goh-Nissim cryptosystem
        Args:
            key_size (int): bit length of the field size p
            plaintext_limit (int): decrypted values must be in [-limit, limit]
        Returns:
            keys (dict): having private_key and public_key keys
        """
        keys = {}
        keys["private_key"] = {}
        keys["public_key"] = {}

        if key_size < 32:
            raise ValueError(f"Key size {key_size} is too small for Freeman-Boneh-Goh-Nissim")

        limit = plaintext_limit or DEFAULT_PLAINTEXT_LIMIT
        r_bits = min(MAX_ORDER_BITS, key_size // 2)
        r = sympy.randprime(2 ** (r_bits - 1), 2**r_bits)
        if 2 * limit + 1 >= r:
            raise ValueError(
                f"Plaintext limit {limit} is too large for the group order of key size {key_size}"
            )

        # p = r l - 1 with 4 | l, so that p = 3 mod 4 and y^2 = x^3 + x has p + 1 = r l points
        l = max(4, (1 << (key_size - r_bits)) // 4 * 4)
        while not sympy.isprime(r * l - 1):
            l += 4
        p = r * l - 1

        # generator P of the subgroup of order r
        while True:
            x = secrets.randbelow(p)
            roots = sqrt_mod((pow(x, 3, p) + x) % p, p, all_roots=True)
            if not roots:
                continue
            ec = LightECC(
                form_name="weierstrass",
                curve_name="custom",
                config={"a": 1, "b": 0, "p": p, "G": (x, roots[0]), "n": None},
            )
            point = EllipticCurvePoint(x, roots[0], ec.curve) * l
            if point.get_point() != ec.O.get_point():
                break
        ec = self.__build_curve(p=p, r=r, point=point.get_point())

        # secret projection v, and H = vectors orthogonal to v
        v = [secrets.randbelow(r - 1) + 1 for _ in range(DIMENSION)]
        while True:
            h1 = self.__random_orthogonal(v, r)
            h2 = self.__random_orthogonal(v, r)
            # h1 and h2 must be linearly independent
            if any(
                (h1[i] * h2[j] - h1[j] * h2[i]) % r != 0
                for i in range(DIMENSION)
                for j in range(i + 1, DIMENSION)
            ):
                break
        while True:
            g = [secrets.randbelow(r) for _ in range(DIMENSION)]
            if sum(x * y for x, y in zip(v, g)) % r != 0:
                break

        keys["public_key"]["p"] = p
        keys["public_key"]["r"] = r
        keys["public_key"]["P"] = ec.G.get_point()
        keys["public_key"]["g"] = [(ec.G * x).get_point() for x in g]
        keys["public_key"]["h1"] = [(ec.G * x).get_point() for x in h1]
        keys["public_key"]["h2"] = [(ec.G * x).get_point() for x in h2]
        keys["public_key"]["limit"] = limit

        keys["private_key"]["v"] = v

        return keys

    def generate_random_key(self) -> Tuple[int, int]:
        """
        Freeman-Boneh-Goh-Nissim requires a pair of random scalars per encryption
        Returns:
            random key (tuple): a1 and a2 in [0, r)
        """
        r = self.keys["public_key"]["r"]
        return secrets.randbelow(r), secrets.randbelow(r)

    def encrypt(self, plaintext: int, random_key: Optional[Tuple[int, int]] = None) -> tuple:
        """
        Encrypt a given plaintext for optionally given random key with Freeman-Boneh-Goh-Nissim
        Args:
            plaintext (int): message to encrypt
            random_key (tuple): random scalars a1 and a2
                Random key will be generated automatically if you do not set this.
        Returns:
            ciphertext (tuple): 3 points of m g + a1 h1 + a2 h2
        """
        r = self.keys["public_key"]["r"]
        a1, a2 = random_key or self.generate_random_key()
        plaintext = plaintext % r

        g = self.__points(self.keys["public_key"]["g"])
        h1 = self.__points(self.keys["public_key"]["h1"])
        h2 = self.__points(self.keys["public_key"]["h2"])
        return tuple(
            (
                self.__scale(gi, plaintext) + self.__scale(h1i, a1) + self.__scale(h2i, a2)
            ).get_point()
            for gi, h1i, h2i in zip(g, h1, h2)
        )

    def decrypt(self, ciphertext: tuple) -> int:
        """
        Decrypt a given ciphertext with Freeman-Boneh-Goh-Nissim
        Args:
            ciphertext (tuple): 3 points, or 9 elements of F_{p^2} if multiplied
        Returns:
            plaintext (int): restored message in [0, r)
        """
        r = self.keys["public_key"]["r"]
        p = self.keys["public_key"]["p"]
        v = self.keys["private_key"]["v"]

        if self.__is_multiplied(ciphertext):
            # product of e(C_i, C'_j)^(v_i v_j) = e(pi(C), pi(C'))
            projected = GT_ONE
            for index, element in enumerate(ciphertext):
                i, j = divmod(index, DIMENSION)
                projected = _fp2_mul(projected, _fp2_pow(tuple(element), (v[i] * v[j]) % r, p), p)
            return self.__discrete_log_gt(projected) % r

        projected = self.__project(self.__points(ciphertext))
        return self.__discrete_log_curve(projected) % r

    def add(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic addition on encrypted data.
        Result of this must be equal to E(m1 + m2)
        A fresh ciphertext is paired with g before it is added to a multiplied one.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Freeman-Boneh-Goh-Nissim
            ciphertext2 (tuple): 2nd ciphertext created with Freeman-Boneh-Goh-Nissim
        Returns:
            ciphertext3 (tuple): 3rd ciphertext created with Freeman-Boneh-Goh-Nissim
        """
        p = self.keys["public_key"]["p"]
        multiplied1 = self.__is_multiplied(ciphertext1)
        multiplied2 = self.__is_multiplied(ciphertext2)

        if not multiplied1 and not multiplied2:
            return tuple(
                (x + y).get_point()
                for x, y in zip(self.__points(ciphertext1), self.__points(ciphertext2))
            )

        # E(m g + h, g) is an encryption of m as a multiplied ciphertext
        if not multiplied1:
            ciphertext1 = self.__pair(ciphertext1, self.keys["public_key"]["g"])
        if not multiplied2:
            ciphertext2 = self.__pair(ciphertext2, self.keys["public_key"]["g"])
        return tuple(_fp2_mul(tuple(x), tuple(y), p) for x, y in zip(ciphertext1, ciphertext2))

    def multiply(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Perform homomorphic multiplication on encrypted data.
        Result of this must be equal to E(m1 * m2). It costs 9 pairings.
        Args:
            ciphertext1 (tuple): 1st ciphertext created with Freeman-Boneh-Goh-Nissim
            ciphertext2 (tuple): 2nd ciphertext created with Freeman-Boneh-Goh-Nissim
        Returns:
            ciphertext3 (tuple): 9 elements of F_{p^2}
        """
        if self.__is_multiplied(ciphertext1) or self.__is_multiplied(ciphertext2):
            raise ValueError(
                "Freeman-Boneh-Goh-Nissim supports only one multiplication. "
                "Multiplied ciphertexts cannot be multiplied with ciphertexts again."
            )
        return self.__pair(ciphertext1, ciphertext2)

    def multiply_by_constant(self, ciphertext: tuple, constant: int) -> tuple:
        """
        Multiply a ciphertext with a plain constant.
        Result of this must be equal to E(m1 * constant) where E(m1) = ciphertext
        Args:
            ciphertext (tuple): ciphertext created with Freeman-Boneh-Goh-Nissim
            constant (int): known plain constant
        Returns:
            ciphertext (tuple): new ciphertext created with Freeman-Boneh-Goh-Nissim
        """
        r = self.keys["public_key"]["r"]
        p = self.keys["public_key"]["p"]
        constant = constant % r

        if self.__is_multiplied(ciphertext):
            return tuple(_fp2_pow(tuple(element), constant, p) for element in ciphertext)
        return tuple(
            self.__scale(point, constant).get_point() for point in self.__points(ciphertext)
        )

    def reencrypt(self, ciphertext: tuple) -> tuple:
        """
        Re-generate ciphertext with re-encryption. Many ciphertext will be decrypted to same plaintext.
        Args:
            ciphertext (tuple): given ciphertext
        Returns:
            new ciphertext (tuple): different ciphertext for same plaintext
        """
        if self.__is_multiplied(ciphertext):
            raise ValueError(
                "Freeman-Boneh-Goh-Nissim can re-encrypt non-multiplied ciphertexts only"
            )
        neutral_element = 0
        neutral_encrypted = self.encrypt(plaintext=neutral_element)
        return self.add(ciphertext1=ciphertext, ciphertext2=neutral_encrypted)

    def __pair(self, ciphertext1: tuple, ciphertext2: tuple) -> tuple:
        """
        Tensor product of two vectors of points with the pairing: e(C_i, C'_j) for all i, j
        """
        points1 = self.__points(ciphertext1)
        points2 = self.__points(ciphertext2)
        identity = self.ec.O.get_point()
        result = []
        for x in points1:
            for y in points2:
                if x.get_point() == identity or y.get_point() == identity:
                    result.append(GT_ONE)
                else:
                    result.append(tuple(self.ec.pairing(x, y)))
        return tuple(result)

    def __project(self, points: List[EllipticCurvePoint]) -> EllipticCurvePoint:
        """
        Secret projection pi(C) = v1 C1 + v2 C2 + v3 C3, which vanishes on H
        """
        v = self.keys["private_key"]["v"]
        result = self.ec.O
        for point, scalar in zip(points, v):
            result = result + self.__scale(point, scalar)
        return result

    def __scale(self, point: EllipticCurvePoint, scalar: int) -> EllipticCurvePoint:
        """
        Scalar multiplication handling the point at infinity, which LightECC cannot multiply
        """
        scalar = scalar % self.keys["public_key"]["r"]
        if scalar == 0 or point.get_point() == self.ec.O.get_point():
            return self.ec.O
        return point * scalar

    def __discrete_log_curve(self, target: EllipticCurvePoint) -> int:
        """
        Find m in [-limit, limit] such that target = m pi(g) with baby-step giant-step
        """
        if "curve" not in self.__tables:
            base = self.__project(self.__points(self.keys["public_key"]["g"]))
            size = math.isqrt(2 * self.keys["public_key"]["limit"]) + 1
            baby_steps = {}
            current = self.ec.O
            for j in range(size):
                baby_steps.setdefault(current.get_point(), j)
                current = current + base
            # giant step is -size * base, and the search starts from target + limit * base
            self.__tables["curve"] = (base, size, baby_steps, self.__scale(base, -size))

        base, size, baby_steps, giant_step = self.__tables["curve"]
        limit = self.keys["public_key"]["limit"]
        current = target + self.__scale(base, limit)
        for i in range(size + 1):
            j = baby_steps.get(current.get_point())
            if j is not None and abs(i * size + j - limit) <= limit:
                return i * size + j - limit
            current = current + giant_step
        raise ValueError(
            f"Decryption failed, because result is out of [-{limit}, {limit}]. "
            "Set a greater plaintext_limit while building the cryptosystem."
        )

    def __discrete_log_gt(self, target: tuple) -> int:
        """
        Find m in [-limit, limit] such that target = e(pi(g), pi(g))^m with baby-step giant-step
        """
        p = self.keys["public_key"]["p"]
        if "gt" not in self.__tables:
            projected_g = self.__project(self.__points(self.keys["public_key"]["g"]))
            base = tuple(self.ec.pairing(projected_g, projected_g))
            size = math.isqrt(2 * self.keys["public_key"]["limit"]) + 1
            baby_steps = {}
            current = GT_ONE
            for j in range(size):
                baby_steps.setdefault(current, j)
                current = _fp2_mul(current, base, p)
            self.__tables["gt"] = (base, size, baby_steps, _fp2_inv(_fp2_pow(base, size, p), p))

        base, size, baby_steps, giant_step = self.__tables["gt"]
        limit = self.keys["public_key"]["limit"]
        current = _fp2_mul(target, _fp2_pow(base, limit, p), p)
        for i in range(size + 1):
            j = baby_steps.get(current)
            if j is not None and abs(i * size + j - limit) <= limit:
                return i * size + j - limit
            current = _fp2_mul(current, giant_step, p)
        raise ValueError(
            f"Decryption failed, because result is out of [-{limit}, {limit}]. "
            "Set a greater plaintext_limit while building the cryptosystem."
        )

    def __points(self, coordinates: tuple) -> List[EllipticCurvePoint]:
        """
        Convert stored coordinates into points on the curve
        """
        identity = self.ec.O.get_point()
        return [
            self.ec.O
            if tuple(point) == identity
            else EllipticCurvePoint(point[0], point[1], self.ec.curve)
            for point in coordinates
        ]

    @staticmethod
    def __is_multiplied(ciphertext: tuple) -> bool:
        return len(ciphertext) == DIMENSION * DIMENSION

    @staticmethod
    def __random_orthogonal(v: List[int], r: int) -> List[int]:
        """
        Random vector x in Z_r^3 such that v . x = 0 mod r
        """
        x1, x2 = secrets.randbelow(r), secrets.randbelow(r)
        x3 = (-(v[0] * x1 + v[1] * x2) * pow(v[2], -1, r)) % r
        return [x1, x2, x3]

    @staticmethod
    def __build_curve(p: int, r: int, point: tuple) -> LightECC:
        """
        Supersingular curve y^2 = x^3 + x over F_p whose generator has prime order r
        """
        return LightECC(
            form_name="weierstrass",
            curve_name="custom",
            config={"a": 1, "b": 0, "p": p, "G": tuple(point), "n": r},
        )
