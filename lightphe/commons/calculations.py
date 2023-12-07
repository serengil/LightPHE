from lightphe.commons.logger import Logger

logger = Logger()

# pylint: disable=no-else-return


def parse_int(value, modulo) -> int:
    if isinstance(value, int) and value >= 0:
        return value
    elif isinstance(value, int) and value < 0:
        return value % modulo
    elif isinstance(value, float) and value >= 0:
        decimal_places = len(str(value).split(".")[1])
        scaling_factor = 10**decimal_places
        integer_value = int(value * scaling_factor)
        logger.debug(f"{integer_value}*{scaling_factor}^-1 mod {modulo}")
        return integer_value * pow(scaling_factor, -1, modulo)
    elif isinstance(value, float) and value < 0:
        # TODO: think and implement this later
        raise ValueError("Case constant float and negative not implemented yet")
    else:
        raise ValueError(f"Unimplemented case for constant type {type(value)}")
