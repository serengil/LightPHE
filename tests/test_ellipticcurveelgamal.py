# built-in dependencies
import time

# 3rd party dependencies
import pytest

# project dependencies
from lightphe.cryptosystems.EllipticCurveElGamal import EllipticCurveElGamal
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_ellipticcurveelgamal.py")

FORMS = [
    (None, None),
    ("weierstrass", None),  # secp256k1
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
    ("weierstrass", "prime192v2"),
    ("weierstrass", "prime192v3"),
    ("weierstrass", "prime239v1"),
    ("weierstrass", "prime239v2"),
    ("weierstrass", "prime239v3"),
    ("weierstrass", "bls12-377"),
    ("weierstrass", "bls12-381"),
    ("weierstrass", "bls12-446"),
    ("weierstrass", "bls12-455"),
    ("weierstrass", "bls12-638"),
    ("weierstrass", "bls24-477"),
    ("weierstrass", "gost256"),
    ("weierstrass", "gost512"),
    ("weierstrass", "bn158"),
    ("weierstrass", "bn190"),
    ("weierstrass", "bn222"),
    ("weierstrass", "bn254"),
    ("weierstrass", "bn286"),
    ("weierstrass", "bn318"),
    ("weierstrass", "bn350"),
    ("weierstrass", "bn382"),
    ("weierstrass", "bn414"),
    ("weierstrass", "bn446"),
    ("weierstrass", "bn478"),
    ("weierstrass", "bn510"),
    ("weierstrass", "bn542"),
    ("weierstrass", "bn574"),
    ("weierstrass", "bn606"),
    ("weierstrass", "bn638"),
    ("weierstrass", "secp112r1"),
    ("weierstrass", "secp112r2"),
    ("weierstrass", "secp128r1"),
    ("weierstrass", "secp128r2"),
    ("weierstrass", "secp160k1"),
    ("weierstrass", "secp160r1"),
    ("weierstrass", "secp160r2"),
    ("weierstrass", "secp192k1"),
    ("weierstrass", "secp224k1"),
    ("edwards", None),  # ed25519
    ("edwards", "ed448"),
    ("edwards", "e521"),
    ("edwards", "curve41417"),
    ("edwards", "jubjub"),
    ("edwards", "mdc201601"),
    ("edwards", "numsp256d1"),
    ("edwards", "numsp384t1"),
    ("edwards", "numsp512t1"),
    ("koblitz", None),  # k163
    ("koblitz", "b163"),
    ("koblitz", "k233"),
    ("koblitz", "b233"),
    ("koblitz", "k283"),
    ("koblitz", "b283"),
    ("koblitz", "k409"),
    ("koblitz", "b409"),
    ("koblitz", "k571"),
    ("koblitz", "b571"),
]


# pylint: disable=expression-not-assigned
def test_elliptic_curve_elgamal():

    for form, curve in FORMS:
        tic = time.time()
        cs = EllipticCurveElGamal(form=form, curve=curve)

        m1 = 10
        m2 = 5

        c1 = cs.encrypt(m1)
        c2 = cs.encrypt(m2)

        # encryption decryption test
        assert cs.decrypt(c1) == m1
        assert cs.decrypt(c2) == m2

        # homomorphic operations
        c3 = cs.add(c1, c2)
        c4 = cs.multiply_by_contant(c1, m2)

        assert cs.decrypt(c3) == m1 + m2
        assert cs.decrypt(c4) == m1 * m2

        # unsupported operations
        with pytest.raises(ValueError):
            cs.multiply(c1, c2)

        with pytest.raises(ValueError):
            cs.xor(c1, c2)

        with pytest.raises(ValueError):
            cs.reencrypt(c1)

        toc = time.time()

        duration = round(toc - tic, 2)

        logger.info(
            f"✅ Elliptic Curve ElGamal test succeeded for EC form {form}&{curve}"
            f" in {duration} seconds"
        )


def test_api():
    from lightphe import LightPHE

    for form, curve in FORMS:
        tic = time.time()
        cs = LightPHE(algorithm_name="EllipticCurve-ElGamal", form=form, curve=curve)

        m1 = 10
        m2 = 5

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

        toc = time.time()
        duration = round(toc - tic, 2)

        logger.info(
            f"✅ Elliptic Curve ElGamal api test succeeded for EC form {form}&{curve}"
            f" in {duration} seconds."
        )
