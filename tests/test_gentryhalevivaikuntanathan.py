import random
import time

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_gentryhalevivaikuntanathan.py")

# smallest lattice dimension keeps tests fast. it is for learning purposes only anyway.
cs = LightPHE(algorithm_name="Gentry-Halevi-Vaikuntanathan", key_size=2)


def test_api():
    tic = time.time()
    modulo = cs.cs.plaintext_modulo

    m1 = 7
    m2 = 9

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
    assert cs.decrypt(c1 * 3) == m1 * 3
    assert cs.decrypt(3 * c1) == m1 * 3

    # negative plaintexts and wrapping around the plaintext modulo
    c3 = cs.encrypt(plaintext=-5)
    assert cs.decrypt(c3) == modulo - 5
    assert cs.decrypt(c1 + c3) == m1 - 5
    assert cs.decrypt(c1 * c3) == modulo - 5 * m1

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
        f"✅ Gentry-Halevi-Vaikuntanathan api test succeeded in {time.time() - tic:.2f} seconds"
    )


def test_insecurity_warning(monkeypatch):
    from lightphe.cryptosystems import GentryHaleviVaikuntanathan as module

    warnings = []
    monkeypatch.setattr(module.logger, "warn", warnings.append)

    LightPHE(algorithm_name="Gentry-Halevi-Vaikuntanathan", keys=cs.cs.keys)
    assert warnings == [module.INSECURE_WARNING_MSG]
    assert "learning purposes only" in warnings[0]

    # other algorithms do not warn
    LightPHE(algorithm_name="Paillier", key_size=64)
    assert len(warnings) == 1


def test_keys_are_well_formed():
    a = cs.cs.keys["public_key"]["A"]
    q = cs.cs.keys["public_key"]["q"]
    p = cs.cs.keys["public_key"]["p"]
    t = cs.cs.keys["private_key"]["T"]
    u = cs.cs.keys["private_key"]["u"]
    m = len(a)

    # trapdoor T is square, short, and T A = 0 mod q
    assert len(t) == m and all(len(row) == m for row in t)
    assert max(abs(x) for row in t for x in row) < q.bit_length() * m
    for row in t:
        for column in zip(*a):
            assert sum(x * y for x, y in zip(row, column)) % q == 0

    # u is the first row of T^-1 modulo p
    for j in range(m):
        expected = 1 if j == 0 else 0
        assert sum(u[i] * t[i][j] for i in range(m)) % p == expected

    assert q & (q - 1) == 0 and p % 2 == 1


def test_degree_2_functions():
    modulo = cs.cs.plaintext_modulo
    for _ in range(10):
        x, y, z = [random.randint(0, modulo - 1) for _ in range(3)]
        k = random.randint(-modulo // 2, modulo // 2)
        cx, cy, cz = cs.encrypt(x), cs.encrypt(y), cs.encrypt(z)

        assert cs.decrypt(cx * cx) == (x * x) % modulo
        assert cs.decrypt((cx + cy) * cz) == ((x + y) * z) % modulo

        # multiplied ciphertexts can be added with each other and with fresh ciphertexts
        assert cs.decrypt(cx * cy + cz * cz + cx) == (x * y + z * z + x) % modulo

        # constants before and after multiplication
        assert cs.decrypt((cx * k) * cy) == (k * x * y) % modulo
        assert cs.decrypt(cx * cy * k) == (k * x * y) % modulo


def test_only_one_multiplication():
    c1, c2, c3 = cs.encrypt(2), cs.encrypt(3), cs.encrypt(4)
    with pytest.raises(ValueError, match="only one multiplication"):
        _ = c1 * c2 * c3

    with pytest.raises(ValueError, match="only one multiplication"):
        _ = c1 * (c2 * c3)


def test_key_size_and_plaintext_limit():
    for key_size in [1, 9, 1024]:
        with pytest.raises(ValueError, match="for learning purposes only"):
            LightPHE(algorithm_name="Gentry-Halevi-Vaikuntanathan", key_size=key_size)

    assert cs.cs.plaintext_modulo == 101

    # plaintext modulus is the smallest prime greater than or equal to the limit
    big_cs = LightPHE(
        algorithm_name="Gentry-Halevi-Vaikuntanathan", key_size=2, plaintext_limit=1000
    )
    assert big_cs.cs.plaintext_modulo == 1009
    x, y = 1000, 999
    assert big_cs.decrypt(big_cs.encrypt(x) * big_cs.encrypt(y)) == (x * y) % 1009


def test_floats_and_tensors_are_not_supported():
    c = cs.encrypt(plaintext=5)
    for plaintext in [1.5, [1, 2, 3]]:
        with pytest.raises(ValueError, match="does not support float"):
            cs.encrypt(plaintext=plaintext)

    with pytest.raises(ValueError, match="does not support float"):
        _ = c * 1.5


def test_catalano_fiore_is_not_needed():
    with pytest.raises(ValueError, match="already supports one multiplication"):
        LightPHE(
            algorithm_name="Gentry-Halevi-Vaikuntanathan", keys=cs.cs.keys, boost="Catalano-Fiore"
        )


def test_exported_keys(tmp_path):
    public_key_file = str(tmp_path / "public.txt")
    cs.export_keys(target_file=public_key_file, public=True)

    # multiplication requires the public key only
    public_cs = LightPHE(algorithm_name="Gentry-Halevi-Vaikuntanathan", key_file=public_key_file)
    c = public_cs.encrypt(plaintext=4) * public_cs.encrypt(plaintext=5) + public_cs.encrypt(1)
    assert cs.decrypt(c) == 21

    with pytest.raises(ValueError, match="private key"):
        public_cs.decrypt(c)

    # private key restored from file
    private_key_file = str(tmp_path / "private.txt")
    cs.export_keys(target_file=private_key_file)
    restored_cs = LightPHE(algorithm_name="Gentry-Halevi-Vaikuntanathan", key_file=private_key_file)
    assert restored_cs.decrypt(c) == 21


def test_default_key_size():
    tic = time.time()
    default_cs = LightPHE(algorithm_name="Gentry-Halevi-Vaikuntanathan")
    assert len(default_cs.cs.keys["public_key"]["A"][0]) == 4

    c1, c2, c3 = default_cs.encrypt(12), default_cs.encrypt(34), default_cs.encrypt(56)
    assert default_cs.decrypt(c1 * c2 + c3) == (12 * 34 + 56) % 101

    logger.info(
        f"✅ Gentry-Halevi-Vaikuntanathan default key size test succeeded in {time.time() - tic:.2f} seconds"
    )
