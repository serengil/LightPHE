import time

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_joyelibert.py")

cs = LightPHE(algorithm_name="Joye-Libert", key_size=50)


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

    # powers of 10 are not invertible in Z_{2^k}, so floats are not supported
    with pytest.raises(ValueError, match="Joye-Libert does not support float"):
        _ = c1 * 1.5

    with pytest.raises(ValueError, match="Joye-Libert does not support float"):
        _ = 1.5 * c1

    with pytest.raises(ValueError, match="Joye-Libert does not support float"):
        _ = cs.encrypt(plaintext=1.5)

    logger.info(f"✅ Joye-Libert api test succeeded in {time.time() - tic:.2f} seconds")


def test_all_plaintexts_in_small_space():
    small_cs = LightPHE(algorithm_name="Joye-Libert", key_size=24)
    modulo = small_cs.cs.plaintext_modulo
    for m in range(modulo):
        assert small_cs.decrypt(small_cs.encrypt(plaintext=m)) == m
    logger.info(f"✅ Joye-Libert restored all {modulo} plaintexts")


def test_api_with_predefined_keys():
    restored_cs = LightPHE(algorithm_name="Joye-Libert", keys=cs.cs.keys)
    m1 = 11
    m2 = 7
    c1 = cs.encrypt(plaintext=m1)
    c2 = restored_cs.encrypt(plaintext=m2)
    assert restored_cs.decrypt(c1 + c2) == m1 + m2
    assert cs.decrypt(c1 + c2) == m1 + m2
    logger.info("✅ Joye-Libert predefined keys test succeeded")


def test_large_keys():
    tic = time.time()
    large_cs = LightPHE(algorithm_name="Joye-Libert", key_size=1024)
    m1 = 123456789
    m2 = 987654321
    c1 = large_cs.encrypt(plaintext=m1)
    c2 = large_cs.encrypt(plaintext=m2)
    assert large_cs.decrypt(c1 + c2) == m1 + m2
    assert large_cs.decrypt(c1 * 1000) == m1 * 1000

    # tensors are still supported because division happens after decryption
    enc_tensor = large_cs.encrypt([1.5, 2.25, 3.5], silent=True)
    assert large_cs.decrypt(enc_tensor) == [1.5, 2.25, 3.5]
    assert large_cs.decrypt(enc_tensor @ [2, 4, 1]) == [15.5]

    # but multiplying a tensor with a float constant is not
    with pytest.raises(ValueError, match="Joye-Libert does not support float"):
        _ = enc_tensor * 1.5
    logger.info(
        f"✅ Joye-Libert 1024-bit key test succeeded in {time.time() - tic:.2f} seconds"
    )
