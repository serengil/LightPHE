import pytest
from lightphe.cryptosystems.ElGamal import ElGamal
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_elgamal.py")


def test_elgamal():
    eg = ElGamal()

    m1 = eg.plaintext_modulo + 100
    m2 = eg.plaintext_modulo + 150

    c1 = eg.encrypt(plaintext=m1)
    c2 = eg.encrypt(plaintext=m2)
    c3 = eg.multiply(c1, c2)

    # homomorphic operations
    assert eg.decrypt(c3) == (m1 * m2) % eg.plaintext_modulo

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        eg.add(c1, c2)

    with pytest.raises(ValueError):
        eg.xor(c1, c2)

    with pytest.raises(ValueError):
        eg.multiply_by_contant(c1, m2)

    # re-encryption
    c1_prime = eg.reencrypt(c1)
    c2_prime = eg.reencrypt(c2)
    c3_prime = eg.reencrypt(c3)
    assert eg.decrypt(c1_prime) == eg.decrypt(c1)
    assert eg.decrypt(c2_prime) == eg.decrypt(c2)
    assert eg.decrypt(c3_prime) == eg.decrypt(c3)

    logger.info("✅ ElGamal test succeeded")


def test_exponential_elgamal():
    additive_eg = ElGamal(exponential=True)

    logger.debug(additive_eg.keys)

    m1 = additive_eg.plaintext_modulo + 222
    m2 = additive_eg.plaintext_modulo + 111

    c1 = additive_eg.encrypt(plaintext=m1)
    c2 = additive_eg.encrypt(plaintext=m2)
    c3 = additive_eg.add(c1, c2)

    # homomorphic operations
    assert additive_eg.decrypt(c3) == (m1 + m2) % additive_eg.plaintext_modulo
    assert (
        additive_eg.decrypt(additive_eg.multiply_by_contant(c1, m2))
        == (m1 * m2) % additive_eg.plaintext_modulo
    )

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        additive_eg.multiply(c1, c2)

    with pytest.raises(ValueError):
        additive_eg.xor(c1, c2)

    # re-encryption
    c1_prime = additive_eg.reencrypt(c1)
    c2_prime = additive_eg.reencrypt(c2)
    c3_prime = additive_eg.reencrypt(c3)
    assert c1_prime != c1
    assert c2_prime != c2
    assert c3_prime != c3
    assert additive_eg.decrypt(c1_prime) == additive_eg.decrypt(c1)
    assert additive_eg.decrypt(c2_prime) == additive_eg.decrypt(c2)
    assert additive_eg.decrypt(c3_prime) == additive_eg.decrypt(c3)

    logger.info("✅ Exponential ElGamal test succeeded")


def test_api_for_multiplicative():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="ElGamal")

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

    cs = LightPHE(algorithm_name="Exponential-ElGamal")

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
