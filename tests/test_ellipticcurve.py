# project dependencies
import pytest

# project dependencies
from lightphe import ECC
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_ellipticcurve.py")


def test_elliptic_curve_interface():
    forms = ["weierstrass", "edwards", "koblitz"]
    for form in forms:
        # construct an elliptic curve for the given form
        ec = ECC(form_name=form, curve_name="test-curve")

        # base point
        G = ec.G

        # order of the curve
        n = ec.n

        for i in range(1, n):
            k = i + 1
            operations = ["G"]
            cumulative_point = G
            for _ in range(0, i):
                cumulative_point = cumulative_point + G
                operations.append("G")

            kG = k * G
            Gk = G * k

            assert kG == Gk
            assert kG == cumulative_point

            logger.debug(f"{'+'.join(operations)} = {cumulative_point}")
            logger.debug(f"""{k} x G = {kG}""")
            logger.debug(f"""G x {k} = {Gk}""")
            logger.debug("--------")

        minus_G = -G
        assert ec.curve.negative_point(P=(G.x, G.y)) == (minus_G.x, minus_G.y)

        _3G = 3 * G
        _5G = 5 * G
        minus_5G = -5 * G
        assert ec.curve.negative_point(P=(_5G.x, _5G.y)) == (minus_5G.x, minus_5G.y)

        _5G_minus_G = _5G - G
        logger.debug(f"""5G - G = {_5G_minus_G}""")

        _3G_plus_G = _3G + G
        logger.debug(f"""3G + G = {_3G_plus_G}""")

        assert _3G_plus_G == _5G_minus_G

        # multiplication cannot be done for 2 points
        with pytest.raises(
            ValueError, match="Multiplication is only defined for an integer"
        ):
            _ = _5G * G

        with pytest.raises(ValueError, match="Addition is only defined for 2 points"):
            _ = _5G + 5

        logger.info(f"✅ Test elliptic curve interface for {form} form done.")


def test_addition_of_2_points_of_different_curves():
    ws = ECC(form_name="weierstrass", curve_name="test-curve")
    ed = ECC(form_name="edwards", curve_name="test-curve")

    with pytest.raises(ValueError, match="Points are not on the same curve"):
        _ = ws.G + ed.G
