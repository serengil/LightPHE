import pytest
from lightphe.cryptosystems.DamgardJurik import DamgardJurik
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_damgard.py")


def test_damgardjurik():
    dg = DamgardJurik()

    m1 = dg.plaintext_modulo + 13
    m2 = dg.plaintext_modulo + 17

    c1 = dg.encrypt(m1)
    c2 = dg.encrypt(m2)

    # homomorphic operations
    assert dg.decrypt(dg.add(c1, c2)) == (m1 + m2) % dg.plaintext_modulo
    assert dg.decrypt(dg.multiply_by_contant(c1, m2)) == (m1 * m2) % dg.plaintext_modulo

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        dg.multiply(c1, c2)

    with pytest.raises(ValueError):
        dg.xor(c1, c2)

    # re-encryption
    c1_prime = dg.reencrypt(c1)
    assert c1_prime != c1
    assert dg.decrypt(c1_prime) == m1 % dg.plaintext_modulo

    logger.info("✅ Damgard-Jurik test succeeded")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Damgard-Jurik")

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

    logger.info("✅ Damgard-Jurik api test succeeded")
