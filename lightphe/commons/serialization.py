# built-in dependencies
import math
from typing import Any, Callable

# 3rd party dependencies
from lightecc.interfaces.elliptic_curve import EllipticCurvePoint

# project dependencies
from lightphe.models.Ciphertext import Ciphertext
from lightphe.models.CatalanoFiore import CatalanoFioreCiphertext
from lightphe.models.Tensor import Fraction, EncryptedTensor

# pylint: disable=too-many-return-statements

# key marking an encoded object that json cannot represent natively
TAG = "__lightphe__"

# version of the encoding, increased if it changes in a backward incompatible way
VERSION = 1

# kinds of objects that need a cryptosystem of the receiver to be restored
CIPHERTEXT = "ciphertext"
CATALANO_FIORE = "catalano-fiore"
TENSOR = "tensor"
POINT = "point"

# kinds of objects restored without a cryptosystem
TUPLE = "tuple"
DICT = "dict"
FLOAT = "float"
FRACTION = "fraction"


def encode(item: Any) -> Any:
    """
    Convert an item into a json serializable form. Keys of the cryptosystem are never
        encoded, receiver restores ciphertexts with its own keys.
    Args:
        item (any): Ciphertext, CatalanoFioreCiphertext, EncryptedTensor, elliptic curve
            point, or int, float, str, bool, None, tuple, list and dict of them, e.g.
            proofs and messages of interactive protocols
    Returns:
        json serializable form of the item
    """
    if item is None or isinstance(item, (bool, int, str)):
        return item
    if isinstance(item, float):
        # identity element of some elliptic curve forms is (inf, inf)
        if math.isfinite(item):
            return item
        return {TAG: FLOAT, "value": str(item)}
    if isinstance(item, list):
        return [encode(i) for i in item]
    if isinstance(item, tuple):
        return {TAG: TUPLE, "items": [encode(i) for i in item]}
    if isinstance(item, dict):
        if all(isinstance(key, str) for key in item.keys()) and TAG not in item:
            return {key: encode(value) for key, value in item.items()}
        return {TAG: DICT, "items": [[encode(key), encode(value)] for key, value in item.items()]}
    if isinstance(item, Ciphertext):
        return {
            TAG: CIPHERTEXT,
            "version": VERSION,
            "algorithm_name": item.algorithm_name,
            "value": encode(item.value),
        }
    if isinstance(item, CatalanoFioreCiphertext):
        return {
            TAG: CATALANO_FIORE,
            "version": VERSION,
            "algorithm_name": item.cf.cs.algorithm_name,
            "a": item.a,
            "beta": encode(item.beta),
            "alpha": encode(item.alpha),
            "pairs": [[encode(beta1), encode(beta2)] for beta1, beta2 in item.pairs],
        }
    if isinstance(item, EncryptedTensor):
        return {
            TAG: TENSOR,
            "version": VERSION,
            "algorithm_name": item.cs.get_algorithm_name(),
            "precision": item.precision,
            "fractions": [encode(fraction) for fraction in item.fractions],
        }
    if isinstance(item, Fraction):
        return {
            TAG: FRACTION,
            "dividend": encode(item.dividend),
            "abs_dividend": encode(item.abs_dividend),
            "divisor": encode(item.divisor),
            "sign": item.sign,
        }
    if isinstance(item, EllipticCurvePoint):
        return {TAG: POINT, "x": encode(item.x), "y": encode(item.y)}
    raise ValueError(f"Object of type {type(item).__name__} cannot be serialized")


def decode(item: Any, restore: Callable[[str, dict], Any]) -> Any:
    """
    Restore an item from its json serializable form created by encode
    Args:
        item (any): json serializable form of the item
        restore (callable): builds ciphertexts, tensors and elliptic curve points
            with the cryptosystem of the receiver. It gets the kind of the object
            and its decoded fields.
    Returns:
        restored item
    """
    if item is None or isinstance(item, (bool, int, float, str)):
        return item
    if isinstance(item, list):
        return [decode(i, restore) for i in item]
    if not isinstance(item, dict):
        raise ValueError(f"Object of type {type(item).__name__} cannot be deserialized")
    if TAG not in item:
        return {key: decode(value, restore) for key, value in item.items()}

    kind = item[TAG]
    if kind == TUPLE:
        return tuple(decode(i, restore) for i in _field(item, "items", list))
    if kind == DICT:
        result = {}
        for pair in _field(item, "items", list):
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError("Items of an encoded dict must be key value pairs")
            key = decode(pair[0], restore)
            try:
                result[key] = decode(pair[1], restore)
            except TypeError as err:
                raise ValueError(f"Key of type {type(key).__name__} is not hashable") from err
        return result
    if kind == FLOAT:
        value = _field(item, "value", str)
        if value not in ["inf", "-inf", "nan"]:
            raise ValueError(f"Invalid encoded float {value}")
        return float(value)
    if kind == FRACTION:
        sign = _field(item, "sign", int)
        if sign not in [1, -1]:
            raise ValueError("Sign of a fraction must be 1 or -1")
        return Fraction(
            dividend=decode_ciphertext_value(item.get("dividend"), restore),
            abs_dividend=decode_ciphertext_value(item.get("abs_dividend"), restore),
            divisor=decode_ciphertext_value(item.get("divisor"), restore),
            sign=sign,
        )
    if kind in [CIPHERTEXT, CATALANO_FIORE, TENSOR]:
        if item.get("version") != VERSION:
            raise ValueError(
                f"Unsupported serialization version {item.get('version')}, expected {VERSION}"
            )
        _field(item, "algorithm_name", str)
    if kind == CIPHERTEXT:
        fields = {
            "algorithm_name": item["algorithm_name"],
            "value": decode_ciphertext_value(item.get("value"), restore),
        }
        return restore(kind, fields)
    if kind == CATALANO_FIORE:
        fields = {
            "algorithm_name": item["algorithm_name"],
            "a": item.get("a"),
            "beta": decode(item.get("beta"), restore),
            "alpha": decode(item.get("alpha"), restore),
            "pairs": [],
        }
        for pair in _field(item, "pairs", list):
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError("Pairs of a Catalano-Fiore ciphertext must have 2 ciphertexts")
            fields["pairs"].append((decode(pair[0], restore), decode(pair[1], restore)))
        return restore(kind, fields)
    if kind == TENSOR:
        fractions = [decode(f, restore) for f in _field(item, "fractions", list)]
        if any(not isinstance(f, Fraction) for f in fractions):
            raise ValueError("Items of an encrypted tensor must be fractions")
        fields = {
            "algorithm_name": item["algorithm_name"],
            "precision": _field(item, "precision", int),
            "fractions": fractions,
        }
        return restore(kind, fields)
    if kind == POINT:
        fields = {"x": decode(item.get("x"), restore), "y": decode(item.get("y"), restore)}
        return restore(kind, fields)
    raise ValueError(f"Unknown serialized object {kind}")


def decode_ciphertext_value(item: Any, restore: Callable[[str, dict], Any]) -> Any:
    """
    Decode the content of a ciphertext, which must consist of integers, tuples and lists
        of them, or elliptic curve points
    Args:
        item (any): json serializable form of the ciphertext content
        restore (callable): builds elliptic curve points with the cryptosystem of the receiver
    Returns:
        ciphertext content (int, tuple, list or elliptic curve point)
    """
    value = decode(item, restore)

    def is_valid(content: Any) -> bool:
        if isinstance(content, EllipticCurvePoint):
            return True
        if isinstance(content, int) and not isinstance(content, bool):
            return True
        if isinstance(content, (tuple, list)):
            return all(is_valid(c) for c in content)
        return False

    if not is_valid(value):
        raise ValueError("Ciphertext must consist of integers, or tuples and lists of them")
    return value


def _field(item: dict, name: str, expected_type: type) -> Any:
    """
    Get a field of an encoded object, and check its type
    """
    value = item.get(name)
    if not isinstance(value, expected_type) or isinstance(value, bool):
        raise ValueError(f"Field {name} of serialized {item[TAG]} must be {expected_type.__name__}")
    return value
