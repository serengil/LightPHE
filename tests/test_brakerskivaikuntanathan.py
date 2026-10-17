import random
import time

import pytest

from lightphe import LightPHE
from lightphe.cryptosystems.BrakerskiVaikuntanathan import LOG_Q, ETA
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_brakerskivaikuntanathan.py")

cs = LightPHE(algorithm_name="Brakerski-Vaikuntanathan", key_size=64)


@pytest.fixture(scope="module")
def large_cs():
    # ring degree giving about 128-bit security against quantum attacks
    return LightPHE(algorithm_name="Brakerski-Vaikuntanathan", key_size=4096)


def negacyclic_product(poly1, poly2, q):
    # schoolbook multiplication in Z_q[x] / (x^d + 1)
    d = len(poly1)
    result = [0] * d
    for i in range(d):
        for j in range(d):
            if i + j < d:
                result[i + j] += poly1[i] * poly2[j]
            else:
                result[i + j - d] -= poly1[i] * poly2[j]
    return [x % q for x in result]


def test_api():
    tic = time.time()
    modulo = cs.cs.plaintext_modulo

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # proof of decryption
    assert cs.decrypt(c1) == m1
    assert cs.decrypt(c2) == m2

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == m1 + m2

    # homomorphic multiplication
    assert cs.decrypt(c1 * c2) == m1 * m2

    # homomorphic scalar multiplication
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2

    # negative plaintexts and addition wrapping around the plaintext modulo
    c3 = cs.encrypt(plaintext=-5)
    assert cs.decrypt(c3) == modulo - 5
    assert cs.decrypt(c1 + c3) == m1 - 5
    assert cs.decrypt(c1 * c3) == modulo - 5 * m1
    assert cs.decrypt(cs.encrypt(plaintext=modulo - 1) + c1) == m1 - 1

    # re-randomization
    c1_prime = cs.regenerate_ciphertext(c1)
    assert c1_prime.value != c1.value
    assert cs.decrypt(c1_prime) == m1

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 ^ c2

    with pytest.raises(ValueError):
        _ = c1 & c2

    logger.info(
        f"✅ Brakerski-Vaikuntanathan api test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_keys_are_well_formed():
    # b = -(a s + t e) where e is small
    public_key = cs.cs.keys["public_key"]
    d, q, t, b = public_key["d"], public_key["q"], public_key["t"], public_key["b"]
    s = cs.cs.keys["private_key"]["s"]
    a = cs.cs._BrakerskiVaikuntanathan__expand(seed=public_key["seed"], d=d)

    assert q.bit_length() == LOG_Q
    assert q % 2 == 1 and t & (t - 1) == 0
    assert all(abs(x) <= ETA for x in s)

    a_s = negacyclic_product(a, [x % q for x in s], q)
    for x, y in zip(a_s, b):
        # t e = -(b + a s)
        t_e = (-(x + y)) % q
        t_e = t_e - q if t_e > q // 2 else t_e
        assert t_e % t == 0 and abs(t_e // t) <= ETA


def test_polynomial_multiplication():
    q = cs.cs.ciphertext_modulo
    multiply = cs.cs._BrakerskiVaikuntanathan__poly_mul
    for d in [8, 64]:
        for _ in range(10):
            poly1 = [random.randrange(q) for _ in range(d)]
            poly2 = [random.randrange(q) for _ in range(d)]
            assert multiply(poly1, poly2, d) == negacyclic_product(poly1, poly2, q)


def test_degree_2_functions():
    modulo = cs.cs.plaintext_modulo
    for _ in range(50):
        x, y, z, k = [random.randint(0, modulo - 1) for _ in range(4)]
        cx, cy, cz = cs.encrypt(x), cs.encrypt(y), cs.encrypt(z)

        assert cs.decrypt(cx * cx) == (x * x) % modulo

        # product of sums, sums of products, and mixing products with fresh ciphertexts
        assert cs.decrypt((cx + cy) * cz) == ((x + y) * z) % modulo
        assert cs.decrypt(cx * cy + cz * cz + cx) == (x * y + z * z + x) % modulo
        assert cs.decrypt(cx + cx * cy) == (x + x * y) % modulo

        # constants before and after multiplication
        assert cs.decrypt((cx * 3) * cy * k) == (3 * x * y * k) % modulo
        assert cs.decrypt(cx * cy * -1) == (-x * y) % modulo


def test_only_one_multiplication():
    c1, c2, c3 = cs.encrypt(2), cs.encrypt(3), cs.encrypt(4)
    with pytest.raises(ValueError, match="only one multiplication"):
        _ = c1 * c2 * c3

    with pytest.raises(ValueError, match="only one multiplication"):
        _ = c1 * (c2 * c3)


def test_plaintext_limit():
    # rounded up to a power of 2
    assert (
        LightPHE(algorithm_name="Brakerski-Vaikuntanathan", key_size=16, plaintext_limit=1000)
        .cs.plaintext_modulo
        == 1024
    )
    assert cs.cs.plaintext_modulo == 2**24

    big_cs = LightPHE(
        algorithm_name="Brakerski-Vaikuntanathan", key_size=16, plaintext_limit=2**32
    )
    x, y = 2**32 - 7, 2**31 + 5
    assert big_cs.decrypt(big_cs.encrypt(x) * big_cs.encrypt(y)) == (x * y) % 2**32

    # product of ciphertexts would not be decrypted correctly
    with pytest.raises(ValueError, match="too large for Brakerski-Vaikuntanathan"):
        LightPHE(algorithm_name="Brakerski-Vaikuntanathan", key_size=16, plaintext_limit=2**45)

    for key_size in [4, 100]:
        with pytest.raises(ValueError, match="must be a power of 2"):
            LightPHE(algorithm_name="Brakerski-Vaikuntanathan", key_size=key_size)


def test_floats_and_tensors_are_not_supported():
    c = cs.encrypt(plaintext=5)
    with pytest.raises(ValueError, match="Brakerski-Vaikuntanathan does not support float"):
        cs.encrypt(plaintext=1.5)

    with pytest.raises(ValueError, match="Brakerski-Vaikuntanathan does not support float"):
        cs.encrypt(plaintext=[1, 2, 3])

    with pytest.raises(ValueError, match="Brakerski-Vaikuntanathan does not support float"):
        _ = c * 1.5


def test_catalano_fiore_is_not_needed():
    with pytest.raises(ValueError, match="already supports one multiplication"):
        LightPHE(algorithm_name="Brakerski-Vaikuntanathan", keys=cs.cs.keys, boost="Catalano-Fiore")


def test_api_with_predefined_keys():
    restored_cs = LightPHE(algorithm_name="Brakerski-Vaikuntanathan", keys=cs.cs.keys)
    m1 = 11
    m2 = 7
    c1 = cs.encrypt(plaintext=m1)
    c2 = restored_cs.encrypt(plaintext=m2)
    assert restored_cs.decrypt(c1 * c2) == m1 * m2
    assert cs.decrypt(c1 + c2) == m1 + m2
    logger.info("✅ Brakerski-Vaikuntanathan predefined keys test succeeded")


def test_exported_keys(tmp_path):
    public_key_file = str(tmp_path / "public.txt")
    cs.export_keys(target_file=public_key_file, public=True)

    # multiplication requires the public key only
    public_cs = LightPHE(algorithm_name="Brakerski-Vaikuntanathan", key_file=public_key_file)
    c = public_cs.encrypt(plaintext=42) * public_cs.encrypt(plaintext=2)
    assert cs.decrypt(c) == 84

    with pytest.raises(ValueError, match="private key"):
        public_cs.decrypt(c)


def test_large_keys(large_cs):
    tic = time.time()
    modulo = large_cs.cs.plaintext_modulo
    xs = [random.randint(0, 1000) for _ in range(5)]
    ys = [random.randint(0, 1000) for _ in range(5)]
    encrypted_xs = [large_cs.encrypt(x) for x in xs]
    encrypted_ys = [large_cs.encrypt(y) for y in ys]

    # dot product of encrypted vectors
    encrypted_dot = encrypted_xs[0] * encrypted_ys[0]
    for ex, ey in zip(encrypted_xs[1:], encrypted_ys[1:]):
        encrypted_dot = encrypted_dot + ex * ey
    assert large_cs.decrypt(encrypted_dot) == sum(x * y for x, y in zip(xs, ys))

    # full range plaintexts with constants after multiplication
    x, y = random.randint(0, modulo - 1), random.randint(0, modulo - 1)
    product = large_cs.encrypt(x) * large_cs.encrypt(y) * 1000
    assert large_cs.decrypt(product) == (1000 * x * y) % modulo

    logger.info(
        f"✅ Brakerski-Vaikuntanathan 4096-degree test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_readme_example(large_cs):
    c1 = large_cs.encrypt(15)
    c2 = large_cs.encrypt(25)
    c3 = large_cs.encrypt(100)

    # one multiplication, then additions and multiplications with constants
    assert large_cs.decrypt(c1 * c2 + c3) == 475
    assert large_cs.decrypt((c1 * c2) * 2 + c1 * c3) == 2250
