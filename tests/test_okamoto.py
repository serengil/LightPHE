import pytest
from lightphe.cryptosystems.OkamotoUchiyama import OkamotoUchiyama
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_okamoto.py")


def test_okamoto():
    cs = OkamotoUchiyama()

    m1 = cs.plaintext_modulo + 123
    m2 = cs.plaintext_modulo + 321
    c1 = cs.encrypt(m1)
    c2 = cs.encrypt(m2)

    # homomorphic operations
    assert cs.decrypt(cs.add(c1, c2)) == (m1 + m2) % cs.plaintext_modulo
    assert cs.decrypt(cs.multiply_by_contant(c1, m2)) == (m1 * m2) % cs.plaintext_modulo

    # unsupported operations
    with pytest.raises(ValueError):
        cs.multiply(c1, c2)

    with pytest.raises(ValueError):
        cs.xor(c1, c2)

    # re-encryption
    c1_prime = cs.reencrypt(c1)
    assert c1_prime != c1
    assert cs.decrypt(c1_prime) == m1 % cs.plaintext_modulo
    logger.info("✅ Okamoto-Uchiyama test succeeded")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Okamoto-Uchiyama")

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == m1 + m2

    # homomorphic scalar multiplication
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(c2 * m1) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2
    assert cs.decrypt(m1 * c2) == m1 * m2

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    logger.info("✅ Okamoto-Uchiyama api test succeeded")
