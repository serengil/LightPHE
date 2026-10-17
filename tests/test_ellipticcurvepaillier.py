import random
import time

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_ellipticcurvepaillier.py")

cs = LightPHE(algorithm_name="EllipticCurve-Paillier", key_size=50)


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
        f"✅ Elliptic Curve Paillier api test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_keys_are_well_formed():
    n = cs.cs.keys["public_key"]["n"]
    b = cs.cs.keys["public_key"]["b"]
    x, y = cs.cs.keys["public_key"]["g"]
    p = cs.cs.keys["private_key"]["p"]
    q = cs.cs.keys["private_key"]["q"]
    order = cs.cs.keys["private_key"]["order"]
    n_square = n * n

    assert n == p * q
    assert p % 3 == 2 and q % 3 == 2

    # g is on the curve y^2 = x^3 + b mod n^2
    assert (y * y - x**3 - b) % n_square == 0

    # order is odd and divides the group exponent modulo n
    assert order % 2 == 1
    assert ((p + 1) * (q + 1)) % order == 0


def test_edge_cases():
    modulo = cs.cs.plaintext_modulo
    for m in [0, 1, 2, modulo - 1]:
        c = cs.encrypt(plaintext=m)
        assert cs.decrypt(c) == m

        # doubling, i.e. adding a ciphertext to itself
        assert cs.decrypt(c + c) == (2 * m) % modulo

        # adding inverse brings point back to the encryption of 0
        assert cs.decrypt(c + c * (modulo - 1)) == 0

        # multiplying by 0 gives the point at infinity, which is the encryption of 0
        assert cs.decrypt(c * 0) == 0
        assert cs.decrypt(c * 0 + c) == m


def test_random_operations():
    modulo = cs.cs.plaintext_modulo
    for _ in range(50):
        m1, m2, k = [random.randint(0, modulo - 1) for _ in range(3)]
        c1 = cs.encrypt(plaintext=m1)
        c2 = cs.encrypt(plaintext=m2)
        assert cs.decrypt(c1 + c2) == (m1 + m2) % modulo
        assert cs.decrypt(c1 * k + c2) == (m1 * k + m2) % modulo


def test_invalid_ciphertext():
    n = cs.cs.plaintext_modulo
    c = cs.encrypt(plaintext=5)
    x, y, z = c.value

    # a point that is not a ciphertext
    with pytest.raises(ValueError, match="invalid"):
        cs.cs.decrypt((x + 1, y, z))

    with pytest.raises(ValueError, match="invalid"):
        cs.cs.decrypt((1, 1, 1 + n))


def test_api_with_predefined_keys():
    restored_cs = LightPHE(algorithm_name="EllipticCurve-Paillier", keys=cs.cs.keys)
    m1 = 11
    m2 = 7
    c1 = cs.encrypt(plaintext=m1)
    c2 = restored_cs.encrypt(plaintext=m2)
    assert restored_cs.decrypt(c1 + c2) == m1 + m2
    assert cs.decrypt(c1 + c2) == m1 + m2
    logger.info("✅ Elliptic Curve Paillier predefined keys test succeeded")


def test_exported_keys(tmp_path):
    public_key_file = str(tmp_path / "public.txt")
    cs.export_keys(target_file=public_key_file, public=True)

    public_cs = LightPHE(algorithm_name="EllipticCurve-Paillier", key_file=public_key_file)
    c = public_cs.encrypt(plaintext=42) * 2
    assert cs.decrypt(c) == 84

    with pytest.raises(ValueError, match="private key"):
        public_cs.decrypt(c)

    # private key restored from file
    private_key_file = str(tmp_path / "private.txt")
    cs.export_keys(target_file=private_key_file)
    restored_cs = LightPHE(algorithm_name="EllipticCurve-Paillier", key_file=private_key_file)
    assert restored_cs.decrypt(c + public_cs.encrypt(plaintext=1)) == 85


def test_large_keys():
    tic = time.time()
    large_cs = LightPHE(algorithm_name="EllipticCurve-Paillier", key_size=1024)
    m1 = 123456789
    m2 = 987654321
    c1 = large_cs.encrypt(plaintext=m1)
    c2 = large_cs.encrypt(plaintext=m2)
    assert large_cs.decrypt(c1 + c2) == m1 + m2
    assert large_cs.decrypt(c1 * 1000) == m1 * 1000

    # floats and tensors
    c3 = large_cs.encrypt(plaintext=1.5)
    assert large_cs.decrypt(c3 * 4) == 6
    enc_tensor = large_cs.encrypt([1.5, 2.25, 3.5], silent=True)
    assert large_cs.decrypt(enc_tensor) == [1.5, 2.25, 3.5]
    assert large_cs.decrypt(enc_tensor @ [2, 4, 1]) == [15.5]

    logger.info(
        f"✅ Elliptic Curve Paillier 1024-bit key test succeeded in {time.time() - tic:.2f} seconds"
    )
