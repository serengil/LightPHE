import math
import random
import secrets
import time

import pytest

from lightphe import LightPHE
from lightphe.cryptosystems.MLKEM import Q, N, PARAMETER_SETS, HALF_Q
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_mlkem.py")

PARAMETER_SET_NAMES = [512, 768, 1024]


@pytest.fixture(scope="module", params=PARAMETER_SET_NAMES)
def cs(request):
    return LightPHE(algorithm_name="ML-KEM", key_size=request.param)


def negacyclic_product(poly1, poly2):
    # schoolbook multiplication in Z_q[x] / (x^256 + 1)
    result = [0] * N
    for i in range(N):
        for j in range(N):
            if i + j < N:
                result[i + j] += poly1[i] * poly2[j]
            else:
                result[i + j - N] -= poly1[i] * poly2[j]
    return [x % Q for x in result]


def centered(x):
    x %= Q
    return x - Q if x > Q // 2 else x


def noise_of(cs, ciphertext, plaintext):
    # v - s^T u - m q / 2 for each coefficient
    s = cs.cs.keys["private_key"]["s"]
    *u, v = ciphertext
    products = [negacyclic_product(u[j], [x % Q for x in s[j]]) for j in range(len(u))]
    return [
        centered(v[x] - sum(column) - ((plaintext >> x) & 1) * HALF_Q)
        for x, column in enumerate(zip(*products))
    ]


def test_api(cs):
    tic = time.time()
    for _ in range(5):
        m1, m2 = secrets.randbits(256), secrets.randbits(256)
        c1 = cs.encrypt(plaintext=m1)
        c2 = cs.encrypt(plaintext=m2)

        # proof of decryption
        assert cs.decrypt(c1) == m1
        assert cs.decrypt(c2) == m2

        # homomorphic exclusive or
        assert cs.decrypt(c1 ^ c2) == m1 ^ m2
        assert cs.decrypt(c1 ^ c1) == 0

    # edge plaintexts and plaintexts exceeding 256 bits
    for m in [0, 1, 2**255, 2**256 - 1]:
        assert cs.decrypt(cs.encrypt(plaintext=m)) == m
    assert cs.decrypt(cs.encrypt(plaintext=2**256 + 5)) == 5
    assert cs.decrypt(cs.encrypt(plaintext=-1)) == 2**256 - 1

    # re-randomization
    c1_prime = cs.regenerate_ciphertext(c1)
    assert c1_prime.value != c1.value
    assert cs.decrypt(c1_prime) == m1

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 + c2

    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 * 3

    with pytest.raises(ValueError):
        _ = c1 & c2

    parameter_set = cs.cs.keys["public_key"]["parameter_set"]
    logger.info(f"✅ ML-KEM-{parameter_set} api test succeeded in {time.time() - tic:.2f} seconds")


def test_parameters_of_fips_203(cs):
    # FIPS 203, table 2
    assert Q == 3329 and N == 256
    assert PARAMETER_SETS == {
        512: {"k": 2, "eta1": 3, "eta2": 2},
        768: {"k": 3, "eta1": 2, "eta2": 2},
        1024: {"k": 4, "eta1": 2, "eta2": 2},
    }

    parameter_set = cs.cs.keys["public_key"]["parameter_set"]
    k = PARAMETER_SETS[parameter_set]["k"]
    c = cs.encrypt(plaintext=1)
    assert len(c.value) == k + 1
    assert all(len(poly) == N and all(0 <= x < Q for x in poly) for poly in c.value)


def test_keys_are_well_formed(cs):
    # t = A s + e where s and e are small
    public_key = cs.cs.keys["public_key"]
    parameters = PARAMETER_SETS[public_key["parameter_set"]]
    k, eta1 = parameters["k"], parameters["eta1"]
    s = cs.cs.keys["private_key"]["s"]
    a = cs.cs._MLKEM__expand(seed=public_key["seed"], k=k)

    assert len(a) == k and all(len(row) == k for row in a)
    assert all(0 <= x < Q for row in a for poly in row for x in poly)
    assert all(abs(x) <= eta1 for poly in s for x in poly)

    for i in range(k):
        a_s = [0] * N
        for j in range(k):
            product = negacyclic_product(a[i][j], [x % Q for x in s[j]])
            a_s = [x + y for x, y in zip(a_s, product)]
        assert all(abs(centered(t - x)) <= eta1 for t, x in zip(public_key["t"][i], a_s))


def test_polynomial_multiplication():
    multiply = LightPHE(algorithm_name="ML-KEM", key_size=512).cs._MLKEM__poly_mul
    for _ in range(5):
        poly1 = [random.randrange(Q) for _ in range(N)]
        poly2 = [random.randrange(-3, 4) for _ in range(N)]
        assert multiply(poly1, poly2) == negacyclic_product(poly1, [x % Q for x in poly2])


def test_noise_matches_the_estimate(cs):
    # noise e^T r + e2 - s^T e1 has variance k * 256 * (var1^2 + var1 * var2) + var2
    parameters = PARAMETER_SETS[cs.cs.keys["public_key"]["parameter_set"]]
    var1, var2 = parameters["eta1"] / 2, parameters["eta2"] / 2
    sigma = math.sqrt(parameters["k"] * N * (var1 * var1 + var1 * var2) + var2)

    samples = []
    for _ in range(4):
        m = secrets.randbits(256)
        samples += noise_of(cs, cs.encrypt(plaintext=m).value, m)
    measured = math.sqrt(sum(x * x for x in samples) / len(samples))
    assert abs(measured - sigma) / sigma < 0.15

    # fresh noise is far below q / 4
    assert max(abs(x) for x in samples) < Q // 4 / 3


def test_exclusive_or_of_many_ciphertexts(cs):
    # failure probability of combining 6 ciphertexts is about 2^-36 or less
    messages = [secrets.randbits(256) for _ in range(6)]
    total = cs.encrypt(plaintext=messages[0])
    expected = messages[0]
    for m in messages[1:]:
        total = total ^ cs.encrypt(plaintext=m)
        expected ^= m
    assert cs.decrypt(total) == expected


def test_floats_and_tensors_are_not_supported():
    cs = LightPHE(algorithm_name="ML-KEM", key_size=512)
    with pytest.raises(ValueError, match="ML-KEM does not support float"):
        cs.encrypt(plaintext=1.5)

    with pytest.raises(ValueError, match="ML-KEM does not support float"):
        cs.encrypt(plaintext=[1, 2, 3])

    for key_size in [256, 1000, 2048]:
        with pytest.raises(ValueError, match="parameter sets of ML-KEM"):
            LightPHE(algorithm_name="ML-KEM", key_size=key_size)


def test_default_parameter_set():
    assert LightPHE(algorithm_name="ML-KEM").cs.keys["public_key"]["parameter_set"] == 768


def test_exported_keys(tmp_path):
    cs = LightPHE(algorithm_name="ML-KEM", key_size=768)
    public_key_file = str(tmp_path / "public.txt")
    private_key_file = str(tmp_path / "private.txt")
    cs.export_keys(target_file=public_key_file, public=True)
    cs.export_keys(target_file=private_key_file)

    m1, m2 = secrets.randbits(256), secrets.randbits(256)
    public_cs = LightPHE(algorithm_name="ML-KEM", key_file=public_key_file)
    c = public_cs.encrypt(plaintext=m1) ^ public_cs.encrypt(plaintext=m2)

    with pytest.raises(ValueError, match="private key"):
        public_cs.decrypt(c)

    restored_cs = LightPHE(algorithm_name="ML-KEM", key_file=private_key_file)
    assert restored_cs.decrypt(c) == m1 ^ m2
    assert cs.decrypt(c) == m1 ^ m2
