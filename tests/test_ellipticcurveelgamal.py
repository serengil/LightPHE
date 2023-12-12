import pytest
from lightphe.cryptosystems.EllipticCurveElGamal import EllipticCurveElGamal
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_ellipticcurveelgamal.py")


def test_elliptic_curve_elgamal():
    cs = EllipticCurveElGamal()

    m1 = 17
    m2 = 33

    c1 = cs.encrypt(m1)
    c2 = cs.encrypt(m2)

    # encryption decryption test
    assert cs.decrypt(c1) == m1
    assert cs.decrypt(c2) == m2

    # homomorphic operations
    c3 = cs.add(c1, c2)
    assert cs.decrypt(c3) == m1 + m2
    assert cs.decrypt(cs.multiply_by_contant(c1, m2)) == m1 * m2

    # unsupported operations
    with pytest.raises(ValueError):
        cs.multiply(c1, c2)

    with pytest.raises(ValueError):
        cs.xor(c1, c2)

    with pytest.raises(ValueError):
        cs.reencrypt(c1)

    logger.info("✅ Elliptic Curve ElGamal test succeeded")


def test_api():
    from lightphe import LightPHE

    cs = LightPHE(algorithm_name="EllipticCurve-ElGamal")

    m1 = 17
    m2 = 21

    c1 = cs.encrypt(plaintext=m1)
    c2 = cs.encrypt(plaintext=m2)

    # homomorphic addition
    assert cs.decrypt(c1 + c2) == m1 + m2
    assert cs.decrypt(c1 * m2) == m1 * m2
    assert cs.decrypt(c2 * m1) == m1 * m2
    assert cs.decrypt(m2 * c1) == m1 * m2
    assert cs.decrypt(m1 * c2) == m1 * m2

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c1 * c2

    with pytest.raises(ValueError):
        _ = c1 ^ c2

    logger.info("✅ Elliptic Curve ElGamal api test succeeded")
