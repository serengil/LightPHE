import pytest
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_elgamal.py")


def test_api_for_multiplicative():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="ElGamal", key_size=50)

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # homomorphic addition
    assert cs.decrypt(c1 * c2) == m1 * m2

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 + c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    with pytest.raises(ValueError):
        _ = c1 * 5

    with pytest.raises(ValueError):
        _ = 5 * c1

    logger.info("✅ ElGamal api test succeeded")


def test_api_for_additive():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Exponential-ElGamal", key_size=50)

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == m1 + m2

    # scalar multiplication
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(c2 * m1) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2
    assert cs.decrypt(m1 * c2) == m1 * m2

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    logger.info("✅ Exponential ElGamal api test succeeded")
