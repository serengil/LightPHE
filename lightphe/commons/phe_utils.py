# built-in dependencies
from typing import Union, Tuple, Optional
from decimal import Decimal, getcontext

# project dependencies
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/commons/phe_utils.py")

# pylint: disable=no-else-return, no-else-break


def normalize_input(value: Union[int, float], modulo: Union[int, str]) -> int:
    """
    Normaliz given value to be in the range of modulo
    Args:
        value (int, float): the value to be normalized
        modulo (int): the modulo value
    Returns:
        result (int, str): the normalized value
    """
    if isinstance(value, int) and isinstance(modulo, str):
        # elliptic curve elgamal & koblitz curves
        result = value % int(modulo, 2)
    elif isinstance(value, int) and isinstance(modulo, int):
        result = value % modulo
    elif isinstance(value, float) and value >= 0:
        dividend, divisor = fractionize(value=value, modulo=modulo)
        logger.debug(f"{dividend}*{divisor}^-1 mod {modulo}")
        result = (dividend * pow(divisor, -1, modulo)) % modulo
    elif isinstance(value, float) and value < 0:
        # TODO: think and implement this later
        raise ValueError("Case constant float and negative not implemented yet")
    else:
        raise ValueError(f"Unimplemented case for constant type {type(value)}")

    return result


def fractionize(
    value: float, modulo: int, precision: Optional[int] = None
) -> Tuple[int, int]:
    getcontext().prec = 50

    if precision is None:
        decimal_places = len(str(value).split(".")[1])
        scaling_factor = 10**decimal_places
    else:
        scaling_factor = 10**precision

    while True:
        integer_value = int(Decimal(value) * Decimal(scaling_factor)) % modulo

        if precision is None:
            break

        if scaling_factor > 10**precision:
            # If scaling factor is too large, discard excess part of integer value
            integer_value = int(
                integer_value / (10 ** (scaling_factor - 10**precision))
            )
            break
        elif scaling_factor < 10 ** (precision - 1):
            # If scaling factor is too small, multiply dividend and divisor 10 times
            value *= 10
            scaling_factor *= 10
        else:
            break

    logger.debug(f"{integer_value}*{scaling_factor}^-1 mod {modulo}")
    return integer_value, scaling_factor


def solve_dlp():
    # TODO: implement this later
    pass
