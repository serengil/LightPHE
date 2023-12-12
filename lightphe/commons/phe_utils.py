from typing import Union, Tuple
from lightphe.commons.logger import Logger

logger = Logger(module="lightphe/commons/phe_utils.py")

# pylint: disable=no-else-return


def parse_int(value: Union[int, float], modulo: int) -> int:
    if isinstance(value, int):
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


def fractionize(value: float, modulo: int, precision=3) -> Tuple[int, int]:
    decimal_places = len(str(value).split(".")[1])
    scaling_factor = 10**decimal_places
    integer_value = int(value * scaling_factor) % modulo

    logger.debug(f"{integer_value}*{scaling_factor}^-1 mod {modulo}")

    # working on same divisor is required to be able to perform homomorphic operations
    if scaling_factor >= pow(10, precision):
        dropped_digits = 0
        while scaling_factor > pow(10, precision):
            scaling_factor = scaling_factor / 10
            dropped_digits += 1
        value_str = str(integer_value)
        value_str = value_str[0 : len(value_str) - dropped_digits]
        integer_value = int(value_str)
        scaling_factor = int(scaling_factor)

    while scaling_factor < pow(10, precision):
        scaling_factor = scaling_factor * 10
        integer_value = integer_value * 10

    logger.debug(f"{integer_value}*{scaling_factor}^-1 mod {modulo}")

    return integer_value, scaling_factor


def solve_dlp():
    # TODO: implement this later
    pass
