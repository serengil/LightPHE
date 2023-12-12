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


def fractionize(value: float, modulo: int) -> Tuple[int, int]:
    decimal_places = len(str(value).split(".")[1])
    scaling_factor = 10**decimal_places
    integer_value = int(value * scaling_factor) % modulo
    logger.debug(f"{integer_value}*{scaling_factor}^-1 mod {modulo}")
    return integer_value, scaling_factor


def solve_dlp():
    # TODO: implement this later
    pass
