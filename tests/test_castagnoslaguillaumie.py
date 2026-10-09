import time

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_castagnoslaguillaumie.py")

cs = LightPHE(algorithm_name="Castagnos-Laguillaumie", key_size=50)


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

    logger.info(f"✅ Castagnos-Laguillaumie api test succeeded in {time.time() - tic:.2f} seconds")


def test_all_plaintexts_in_small_space():
    small_cs = LightPHE(algorithm_name="Castagnos-Laguillaumie", key_size=24)
    modulo = small_cs.cs.plaintext_modulo
    for m in range(modulo):
        assert small_cs.decrypt(small_cs.encrypt(plaintext=m)) == m
    logger.info(f"✅ Castagnos-Laguillaumie restored all {modulo} plaintexts")


def test_api_with_predefined_keys():
    restored_cs = LightPHE(algorithm_name="Castagnos-Laguillaumie", keys=cs.cs.keys)
    m1 = 11
    m2 = 7
    c1 = cs.encrypt(plaintext=m1)
    c2 = restored_cs.encrypt(plaintext=m2)
    assert restored_cs.decrypt(c1 + c2) == m1 + m2
    assert cs.decrypt(c1 + c2) == m1 + m2
    logger.info("✅ Castagnos-Laguillaumie predefined keys test succeeded")


def test_large_keys():
    tic = time.time()
    large_cs = LightPHE(algorithm_name="Castagnos-Laguillaumie", key_size=1024)
    m1 = 123456789
    m2 = 987654321
    c1 = large_cs.encrypt(plaintext=m1)
    c2 = large_cs.encrypt(plaintext=m2)
    assert large_cs.decrypt(c1 + c2) == m1 + m2
    assert large_cs.decrypt(c1 * 1000) == m1 * 1000
    logger.info(
        f"✅ Castagnos-Laguillaumie 1024-bit key test succeeded in {time.time() - tic:.2f} seconds"
    )
