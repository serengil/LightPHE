import pytest
from lightphe.cryptosystems.Benaloh import Benaloh
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_benaloh.py")


def test_benaloh():
    bn = Benaloh()

    m1 = bn.plaintext_modulo + 18
    m2 = bn.plaintext_modulo + 22

    c1 = bn.encrypt(m1)
    c2 = bn.encrypt(m2)

    # supported homomorphic operations
    assert bn.decrypt(bn.add(c1, c2)) == (m1 + m2) % bn.plaintext_modulo
    assert bn.decrypt(bn.multiply_by_contant(c1, m2)) == (m1 * m2) % bn.plaintext_modulo

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        bn.multiply(c1, m2)

    with pytest.raises(ValueError):
        bn.xor(c1, c2)

    # re-encryption
    c1_prime = bn.reencrypt(c1)
    assert c1_prime != c1
    assert bn.decrypt(c1_prime) == m1 % bn.plaintext_modulo

    logger.info("✅ Benaloh test succeeded")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="Benaloh")

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

    logger.info("✅ Benaloh api test succeeded")
