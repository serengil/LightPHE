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


def test_adding_a_point_with_its_negative():
    for form in FORMS:
        cs = EllipticCurveElGamal(form=form)
        G = cs.ecc.curve.G
        G_minus = cs.ecc.curve.negative_point(G)
        assert cs.ecc.curve.O == cs.ecc.curve.add_points(G, G_minus)

        logger.info(f"✅ Adding a point with its negative tested for {form}")


def test_zero_times_base_point():
    for form in FORMS:
        cs = EllipticCurveElGamal(form=form)
        G = cs.ecc.curve.G
        assert cs.ecc.curve.double_and_add(G, 0) == cs.ecc.curve.O
        logger.info(f"✅ Test 0 x G = O done for {form}")


def test_double_and_add_with_negative_input():
    for form in FORMS:
        cs = EllipticCurveElGamal(form=form)
        G = cs.ecc.curve.G
        assert cs.ecc.curve.double_and_add(G, -10) == cs.ecc.curve.negative_point(
            cs.ecc.curve.double_and_add(G, 10)
        )
        logger.info(f"✅ Test (-10) x G = -(10 x G) done for {form}")


def test_elliptic_curve_cyclic_group_on_test_curve():

    curves = ["weierstrass", "koblitz", "edwards"]

    for form in curves:
        logger.debug(f"ℹ️ Testing elliptic curve cyclic group on {form} test curve")
        cs = EllipticCurveElGamal(form=form, curve="test-curve")

        for k in range(0, 2 * cs.ecc.curve.n + 1):
            P = cs.ecc.curve.double_and_add(cs.ecc.curve.G, k)
            logger.debug(f"{k} x G = {P}")

            if k in [0, cs.ecc.curve.n]:
                assert P == cs.ecc.curve.O

        logger.info(f"✅ Test elliptic curve cyclic group on test {form} curve done.")


def test_weierstrass_point_addition_returning_point_at_infinity():
    cs = EllipticCurveElGamal(form="weierstrass", curve="test-curve")

    # we know that 20G + 8G = 28G = point at infinity
    P = cs.ecc.curve.add_points(
        cs.ecc.curve.double_and_add(cs.ecc.curve.G, 20),
        cs.ecc.curve.double_and_add(cs.ecc.curve.G, 8),
    )
    assert P == cs.ecc.curve.O

    _14G = cs.ecc.curve.double_and_add(cs.ecc.curve.G, 14)
    Q = cs.ecc.curve.add_points(_14G, _14G)
    assert Q == cs.ecc.curve.O

    logger.info("✅ Test weierstras point addition returning point at infinity done.")


def test_koblitz_point_addition_returning_point_at_infinity():
    cs = EllipticCurveElGamal(form="koblitz", curve="test-curve")

    # we know that 12G + 4G = 16G = point at infinity
    P = cs.ecc.curve.add_points(
        cs.ecc.curve.double_and_add(cs.ecc.curve.G, 12),
        cs.ecc.curve.double_and_add(cs.ecc.curve.G, 4),
    )
    assert P == cs.ecc.curve.O

    _8G = cs.ecc.curve.double_and_add(cs.ecc.curve.G, 8)
    Q = cs.ecc.curve.add_points(_8G, _8G)
    assert Q == cs.ecc.curve.O

    logger.info("✅ Test koblitz point addition returning point at infinity done.")


def test_edwards_point_addition_returning_point_at_infinity():
    cs = EllipticCurveElGamal(form="edwards", curve="test-curve")

    # we know that 6G + 2G = 8G = point at infinity
    P = cs.ecc.curve.add_points(
        cs.ecc.curve.double_and_add(cs.ecc.curve.G, 6),
        cs.ecc.curve.double_and_add(cs.ecc.curve.G, 2),
    )
    assert P == cs.ecc.curve.O

    _4G = cs.ecc.curve.double_and_add(cs.ecc.curve.G, 4)
    Q = cs.ecc.curve.add_points(_4G, _4G)
    assert Q == cs.ecc.curve.O

    logger.info("✅ Test edwards point addition returning point at infinity done.")


def test_double_and_add_for_k_close_to_n():
    for form in FORMS:
        cs = EllipticCurveElGamal(form=form)

        _ = cs.ecc.curve.double_and_add(cs.ecc.curve.G, cs.ecc.curve.n - 1)
        assert (
            cs.ecc.curve.double_and_add(cs.ecc.curve.G, cs.ecc.curve.n)
            == cs.ecc.curve.O
        )
        assert (
            cs.ecc.curve.double_and_add(cs.ecc.curve.G, cs.ecc.curve.n + 1)
            == cs.ecc.curve.G
        )

        logger.info(
            f"✅ Double and add for k being close to order test done for {form}"
        )


def test_add_neutral_point():
    for form in FORMS:
        cs = EllipticCurveElGamal(form=form)

        _7G = cs.ecc.curve.double_and_add(cs.ecc.curve.G, 7)

        assert cs.ecc.curve.add_points(_7G, cs.ecc.curve.O) == _7G
        assert cs.ecc.curve.add_points(cs.ecc.curve.O, _7G) == _7G
        assert cs.ecc.curve.add_points(cs.ecc.curve.O, cs.ecc.curve.O) == cs.ecc.curve.O

        logger.info(f"✅ Adding neutral point test done for {form}")
