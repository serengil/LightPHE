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
def __test_build_curves():
    summary = []
    logger.info("| form | curve | field | n (bits)|")
    for form in FORMS:
        curves = inventory.list_curves(form)
        for curve in curves:
            cs = EllipticCurveElGamal(form=form, curve=curve)
            field = "binary" if form == "koblitz" else "prime"
            logger.info(f"| {form} | {curve} | {field} | {cs.curve.n.bit_length()} |")
            summary.append((form, curve, field, cs.curve.n.bit_length()))

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
                f" ({cs.curve.n.bit_length()}-bit) in {duration} seconds"
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


def test_adding_a_point_with_its_negative():
    for form in FORMS:
        cs = EllipticCurveElGamal(form=form)
        G = cs.curve.G
        G_minus = cs.curve.negative_point(G)
        assert cs.curve.O == cs.curve.add_points(G, G_minus)

        logger.info(f"✅ Adding a point with its negative tested for {form}")


def test_zero_times_base_point():
    for form in FORMS:
        cs = EllipticCurveElGamal(form=form)
        G = cs.curve.G
        assert cs.curve.double_and_add(G, 0) == cs.curve.O
        logger.info(f"✅ Test 0 x G = O done for {form}")


def test_double_and_add_with_negative_input():
    for form in FORMS:
        cs = EllipticCurveElGamal(form=form)
        G = cs.curve.G
        assert cs.curve.double_and_add(G, -10) == cs.curve.negative_point(
            cs.curve.double_and_add(G, 10)
        )
        logger.info(f"✅ Test (-10) x G = -(10 x G) done for {form}")


def test_elliptic_curve_cyclic_group_on_test_curve():
    cs = EllipticCurveElGamal(form="weierstrass", curve="test-curve-pf-23")

    for k in range(0, 5 * cs.curve.n):
        P = cs.curve.double_and_add(cs.curve.G, k)
        logger.debug(f"{k} x G = {P}")

        if k in [0, cs.curve.n]:
            assert P == cs.curve.O

    logger.info("✅ Test elliptic curve cyclic group on test curve done.")


def test_point_addition_returning_point_at_infinity():
    cs = EllipticCurveElGamal(form="weierstrass", curve="test-curve-pf-23")

    # we know that 20G + 8 G = 28G = point at infinity
    P = cs.curve.add_points(
        cs.curve.double_and_add(cs.curve.G, 20), cs.curve.double_and_add(cs.curve.G, 8)
    )
    assert P == cs.curve.O

    _14G = cs.curve.double_and_add(cs.curve.G, 14)
    Q = cs.curve.add_points(_14G, _14G)
    assert Q == cs.curve.O

    logger.info("✅ Test elliptic curve cyclic group on test curve done.")


def test_double_and_add_for_k_close_to_n():
    for form in FORMS:
        cs = EllipticCurveElGamal(form=form)

        _ = cs.curve.double_and_add(cs.curve.G, cs.curve.n - 1)
        assert cs.curve.double_and_add(cs.curve.G, cs.curve.n) == cs.curve.O
        assert cs.curve.double_and_add(cs.curve.G, cs.curve.n + 1) == cs.curve.G

        logger.info(
            f"✅ Double and add for k being close to order test done for {form}"
        )


def test_add_neutral_point():
    for form in FORMS:
        cs = EllipticCurveElGamal(form=form)

        _7G = cs.curve.double_and_add(cs.curve.G, 7)

        assert cs.curve.add_points(_7G, cs.curve.O) == _7G
        assert cs.curve.add_points(cs.curve.O, _7G) == _7G
        assert cs.curve.add_points(cs.curve.O, cs.curve.O) == cs.curve.O

        logger.info(f"✅ Adding neutral point test done for {form}")
