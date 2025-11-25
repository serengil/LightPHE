# built-in dependencies
import time

# 3rd party dependencies
import pytest
from lightecc.curves import inventory

# project dependencies
from lightphe.cryptosystems.EllipticCurveElGamal import EllipticCurveElGamal
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_ellipticcurveelgamal.py")

FORMS = ["weierstrass", "edwards", "koblitz"]


# pylint: disable=expression-not-assigned
def __test_build_curves():
    summary = []
    logger.info("| form | curve | field | n (bits)|")
    for form in FORMS:
        curves = inventory.list_curves(form)
        for curve in curves:
            cs = EllipticCurveElGamal(form=form, curve=curve)
            field = "binary" if form == "koblitz" else "prime"
            logger.info(
                f"| {form} | {curve} | {field} | {cs.ecc.curve.n.bit_length()} |"
            )
            summary.append((form, curve, field, cs.ecc.curve.n.bit_length()))

    import pandas as pd

    df = pd.DataFrame(summary, columns=["form", "curve", "field", "n (bits)"])
    df = df.sort_values(by=["form", "n (bits)"], ascending=[True, False])

    logger.info("| form | curve | field | n (bits)|")
    for _, instance in df.iterrows():
        logger.info(
            f"| {instance['form']} | {instance['curve']} | {instance['field']} | {instance['n (bits)']} |"
        )


def __test_elliptic_curve_elgamal():
    for form in FORMS:
        curves = inventory.list_curves(form)
        for curve in curves:

            if curve in ["test-curve"]:
                continue

            logger.debug(
                f"ℹ️ Elliptic Curve ElGamal test is running for EC form {form}&{curve}"
            )

            tic = time.time()

            try:
                cs = EllipticCurveElGamal(form=form, curve=curve)
            except Exception as err:
                raise ValueError(
                    f"❌ Elliptic Curve ElGamal test failed for EC form {form}&{curve}"
                ) from err

            m1 = 10
            m2 = 5

            c1 = cs.encrypt(m1)
            c2 = cs.encrypt(m2)

            # encryption decryption test
            assert cs.decrypt(c1) == m1
            assert cs.decrypt(c2) == m2

            # homomorphic operations
            c3 = cs.add(c1, c2)
            c4 = cs.multiply_by_constant(c1, m2)

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
                f" ({cs.ecc.curve.n.bit_length()}-bit) in {duration} seconds"
            )


def test_api():
    from lightphe import LightPHE

    for form in FORMS:
        tic = time.time()
        cs = LightPHE(algorithm_name="EllipticCurve-ElGamal", form=form, curve=None)

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
            f"✅ Elliptic Curve ElGamal api test succeeded for EC form {form}"
            f" in {duration} seconds."
        )
