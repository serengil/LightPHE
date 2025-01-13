# built-in dependencies
import time

# 3rd party dependencies
import pytest

# project dependencies
from lightphe.cryptosystems.EllipticCurveElGamal import EllipticCurveElGamal
from lightphe.standard_curves import inventory
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_ellipticcurveelgamal.py")

FORMS = ["weierstrass", "edwards", "koblitz"]


# pylint: disable=expression-not-assigned
def test_elliptic_curve_elgamal():

    for form in FORMS:
        curves = inventory.list_curves(form)
        for curve in curves:

            # exclude these because they take too long
            if form == "koblitz" and curve not in ["k163", "b163"]:
                continue

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

    for form in FORMS:
        curves = inventory.list_curves(form)
        for curve in curves:
            # exclude these because they take too long
            if form == "koblitz" and curve not in ["k163", "b163"]:
                continue

            tic = time.time()
            cs = LightPHE(
                algorithm_name="EllipticCurve-ElGamal", form=form, curve=curve
            )

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
