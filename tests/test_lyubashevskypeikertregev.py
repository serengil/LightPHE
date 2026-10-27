import random
import time

import pytest

from lightphe import LightPHE
from lightphe.cryptosystems.LyubashevskyPeikertRegev import LOG_Q, ETA
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_lyubashevskypeikertregev.py")

cs = LightPHE(algorithm_name="Lyubashevsky-Peikert-Regev", key_size=64)


@pytest.fixture(scope="module")
def large_cs():
    # ring degree giving about 128-bit security against quantum attacks
    return LightPHE(algorithm_name="Lyubashevsky-Peikert-Regev", key_size=2048)


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

    # homomorphic scalar multiplication
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2

    # negative plaintexts and addition wrapping around the plaintext modulo
    c3 = cs.encrypt(plaintext=-5)
    assert cs.decrypt(c3) == modulo - 5
    assert cs.decrypt(c1 + c3) == m1 - 5
    assert cs.decrypt(cs.encrypt(plaintext=modulo - 1) + c1) == m1 - 1

    # re-randomization
    c1_prime = cs.regenerate_ciphertext(c1)
    assert c1_prime.value != c1.value
    assert cs.decrypt(c1_prime) == m1

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    with pytest.raises(ValueError):
        _ = c1 & c2

    logger.info(
        f"✅ Lyubashevsky-Peikert-Regev api test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_keys_are_well_formed():
    # b = a s + e where e is small
    public_key = cs.cs.keys["public_key"]
    d, q, b = public_key["d"], public_key["q"], public_key["b"]
    s = cs.cs.keys["private_key"]["s"]
    a = cs.cs._LyubashevskyPeikertRegev__expand(seed=public_key["seed"], d=d)

    assert q == 2**LOG_Q
    assert len(a) == d and len(b) == d and len(s) == d
    assert all(0 <= x < q for x in a)
    assert all(abs(x) <= ETA for x in s)

    a_s = negacyclic_product(a, [x % q for x in s], q)
    for x, y in zip(a_s, b):
        error = (y - x) % q
        error = error - q if error > q // 2 else error
        assert abs(error) <= ETA


def test_ciphertexts_are_well_formed():
    # c1 = a u + e1 and c2 = constant term of b u + e2 + m q / t, where u, e1, e2 are small
    public_key = cs.cs.keys["public_key"]
    d, q, t, b = public_key["d"], public_key["q"], public_key["t"], public_key["b"]
    a = cs.cs._LyubashevskyPeikertRegev__expand(seed=public_key["seed"], d=d)
    u = cs.cs.generate_random_key()
    m = 12345

    *c1, c2 = cs.cs.encrypt(plaintext=m, random_key=u)
    assert len(c1) == d

    a_u = negacyclic_product(a, [x % q for x in u], q)
    for x, y in zip(a_u, c1):
        error = (y - x) % q
        error = error - q if error > q // 2 else error
        assert abs(error) <= ETA

    b_u = negacyclic_product(b, [x % q for x in u], q)
    error = (c2 - b_u[0] - m * (q // t)) % q
    error = error - q if error > q // 2 else error
    assert abs(error) <= ETA


def test_polynomial_multiplication():
    q = cs.cs.ciphertext_modulo
    multiply = cs.cs._LyubashevskyPeikertRegev__poly_mul
    for d in [8, 64]:
        for _ in range(10):
            poly1 = [random.randrange(q) for _ in range(d)]
            poly2 = [random.randrange(q) for _ in range(d)]
            assert multiply(poly1, poly2, d) == negacyclic_product(poly1, poly2, q)


def test_all_plaintexts_of_small_space():
    small_cs = LightPHE(algorithm_name="Lyubashevsky-Peikert-Regev", key_size=32, plaintext_limit=16)
    assert small_cs.cs.plaintext_modulo == 16
    for m in range(16):
        assert small_cs.decrypt(small_cs.encrypt(plaintext=m)) == m


def test_plaintext_limit():
    # rounded up to a power of 2
    assert (
        LightPHE(algorithm_name="Lyubashevsky-Peikert-Regev", key_size=32, plaintext_limit=1000)
        .cs.plaintext_modulo
        == 1024
    )
    assert LightPHE(algorithm_name="Lyubashevsky-Peikert-Regev", key_size=32).cs.plaintext_modulo == 2**24

    big_cs = LightPHE(algorithm_name="Lyubashevsky-Peikert-Regev", key_size=32, plaintext_limit=2**32)
    m = 2**32 - 7
    assert big_cs.decrypt(big_cs.encrypt(plaintext=m)) == m

    # no room for noise
    with pytest.raises(ValueError, match="too large for Lyubashevsky-Peikert-Regev"):
        LightPHE(algorithm_name="Lyubashevsky-Peikert-Regev", key_size=32, plaintext_limit=2**45)

    # ring degree must be a power of 2
    for key_size in [4, 48, 100]:
        with pytest.raises(ValueError, match="must be a power of 2"):
            LightPHE(algorithm_name="Lyubashevsky-Peikert-Regev", key_size=key_size)


def test_noise_budget():
    modulo = cs.cs.plaintext_modulo
    m = 4567
    c = cs.encrypt(plaintext=m)

    # many additions
    total = cs.encrypt(plaintext=0)
    for _ in range(1000):
        total = total + c
    assert cs.decrypt(total) == (1000 * m) % modulo

    # large and negative constants
    assert cs.decrypt(c * 4000) == (4000 * m) % modulo
    assert cs.decrypt(c * -3) == (-3 * m) % modulo
    assert cs.decrypt(c * (modulo - 1)) == (-m) % modulo

    # random linear combinations
    for _ in range(20):
        values = [random.randint(0, 1000) for _ in range(5)]
        weights = [random.randint(-50, 50) for _ in range(5)]
        encrypted = [cs.encrypt(plaintext=v) for v in values]
        result = encrypted[0] * weights[0]
        for c_i, w_i in zip(encrypted[1:], weights[1:]):
            result = result + c_i * w_i
        assert cs.decrypt(result) == sum(v * w for v, w in zip(values, weights)) % modulo


def test_floats_and_tensors_are_not_supported():
    c = cs.encrypt(plaintext=5)
    with pytest.raises(ValueError, match="Lyubashevsky-Peikert-Regev does not support float"):
        cs.encrypt(plaintext=1.5)

    with pytest.raises(ValueError, match="Lyubashevsky-Peikert-Regev does not support float"):
        cs.encrypt(plaintext=[1, 2, 3])

    with pytest.raises(ValueError, match="Lyubashevsky-Peikert-Regev does not support float"):
        _ = c * 1.5


def test_api_with_predefined_keys():
    restored_cs = LightPHE(algorithm_name="Lyubashevsky-Peikert-Regev", keys=cs.cs.keys)
    m1 = 11
    m2 = 7
    c1 = cs.encrypt(plaintext=m1)
    c2 = restored_cs.encrypt(plaintext=m2)
    assert restored_cs.decrypt(c1 + c2) == m1 + m2
    assert cs.decrypt(c1 + c2) == m1 + m2
    logger.info("✅ Lyubashevsky-Peikert-Regev predefined keys test succeeded")


def test_exported_keys(tmp_path):
    public_key_file = str(tmp_path / "public.txt")
    cs.export_keys(target_file=public_key_file, public=True)

    public_cs = LightPHE(algorithm_name="Lyubashevsky-Peikert-Regev", key_file=public_key_file)
    c = public_cs.encrypt(plaintext=42) * 2
    assert cs.decrypt(c) == 84

    with pytest.raises(ValueError, match="private key"):
        public_cs.decrypt(c)


def test_large_keys(large_cs):
    tic = time.time()
    modulo = large_cs.cs.plaintext_modulo
    m1 = 1234567
    m2 = 7654321
    c1 = large_cs.encrypt(plaintext=m1)
    c2 = large_cs.encrypt(plaintext=m2)
    assert len(c1.value) == 2048 + 1

    assert large_cs.decrypt(c1) == m1
    assert large_cs.decrypt(c1 + c2) == m1 + m2
    assert large_cs.decrypt(c1 * 1000) == (m1 * 1000) % modulo
    assert large_cs.decrypt(c1 * -1000 + c2 * 3) == (-1000 * m1 + 3 * m2) % modulo

    total = large_cs.encrypt(plaintext=0)
    for _ in range(1000):
        total = total + c1
    assert large_cs.decrypt(total) == (1000 * m1) % modulo

    logger.info(
        f"✅ Lyubashevsky-Peikert-Regev 2048-degree test succeeded in {time.time() - tic:.2f} seconds"
    )
