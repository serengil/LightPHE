import pytest
from lightphe.cryptosystems.EllipticCurveElGamal import EllipticCurveElGamal
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_ellipticcurveelgamal.py")

FORMS = [
    (None, None),
    ("weierstrass", None),
    ("weierstrass", "secp256k1"),
    ("weierstrass", "p192"),
    ("weierstrass", "p224"),
    ("weierstrass", "p256"),
    ("weierstrass", "p384"),
    ("weierstrass", "p521"),
    ("weierstrass", "curve22103"),
    ("weierstrass", "curve4417"),
    ("weierstrass", "curve1174"),
    ("weierstrass", "curve67254"),
    ("weierstrass", "fp254bna"),
    ("weierstrass", "fp254bnb"),
    ("weierstrass", "fp224bn"),
    ("weierstrass", "fp256bn"),
    ("weierstrass", "fp384bn"),
    ("weierstrass", "fp512bn"),
    ("weierstrass", "tweedledum"),
    ("weierstrass", "tweedledee"),
    ("weierstrass", "pallas"),
    ("weierstrass", "vesta"),
    ("weierstrass", "tom256"),
    ("weierstrass", "numsp256d1"),
    ("weierstrass", "numsp384d1"),
    ("weierstrass", "numsp512d1"),
    ("weierstrass", "brainpoolP160r1"),
    ("weierstrass", "brainpoolP160t1"),
    ("weierstrass", "brainpoolP192r1"),
    ("weierstrass", "brainpoolP192t1"),
    ("weierstrass", "brainpoolP224r1"),
    ("weierstrass", "brainpoolP224t1"),
    ("weierstrass", "brainpoolP256r1"),
    ("weierstrass", "brainpoolP256t1"),
    ("weierstrass", "brainpoolP320r1"),
    ("weierstrass", "brainpoolP320t1"),
    ("weierstrass", "brainpoolP384r1"),
    ("weierstrass", "brainpoolP384t1"),
    ("weierstrass", "brainpoolP512r1"),
    ("weierstrass", "brainpoolP512t1"),
    ("weierstrass", "mnt1"),
    ("weierstrass", "mnt2/1"),
    ("weierstrass", "mnt2/2"),
    ("weierstrass", "mnt3/1"),
    ("weierstrass", "mnt3/2"),
    ("weierstrass", "mnt3/3"),
    ("weierstrass", "mnt4"),
    ("weierstrass", "mnt5/1"),
    ("weierstrass", "mnt5/2"),
    ("weierstrass", "mnt5/3"),
    ("edwards", None),
    ("edwards", "ed448"),
    ("edwards", "e521"),
    ("edwards", "curve41417"),
    ("edwards", "jubjub"),
    ("edwards", "mdc201601"),
    ("edwards", "numsp256d1"),
    ("edwards", "numsp384t1"),
    ("edwards", "numsp512t1"),
]


def test_elliptic_curve_elgamal():

    for form, curve in FORMS:
        cs = EllipticCurveElGamal(form=form, curve=curve)

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

        logger.info(
            f"✅ Elliptic Curve ElGamal test succeeded for EC form {form}&{curve}"
        )


def test_api():
    from lightphe import LightPHE

    for form, curve in FORMS:
        cs = LightPHE(algorithm_name="EllipticCurve-ElGamal", form=form, curve=curve)

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

        logger.info(
            f"✅ Elliptic Curve ElGamal api test succeeded for EC form {form}&{curve}"
        )
