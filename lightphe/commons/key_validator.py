from typing import Dict, Type

from lightphe.models.Algorithm import Algorithm
from lightphe.models.Homomorphic import Homomorphic
from lightphe.cryptosystems.RSA import RSA
from lightphe.cryptosystems.ElGamal import ElGamal
from lightphe.cryptosystems.EllipticCurveElGamal import EllipticCurveElGamal
from lightphe.cryptosystems.Paillier import Paillier
from lightphe.cryptosystems.DamgardJurik import DamgardJurik
from lightphe.cryptosystems.OkamotoUchiyama import OkamotoUchiyama
from lightphe.cryptosystems.Benaloh import Benaloh
from lightphe.cryptosystems.NaccacheStern import NaccacheStern
from lightphe.cryptosystems.GoldwasserMicali import GoldwasserMicali
from lightphe.cryptosystems.SanderYoungYung import SanderYoungYung
from lightphe.cryptosystems.BonehGohNissim import BonehGohNissim


# Map user-facing algorithm names to the class that owns the REQUIRED_KEYS spec.
# The spec itself lives as a class attribute on each cryptosystem.
# Exponential-ElGamal reuses ElGamal's key structure.
_ALGORITHM_TO_CLASS: Dict[str, Type[Homomorphic]] = {
    Algorithm.RSA: RSA,
    Algorithm.ElGamal: ElGamal,
    Algorithm.ExponentialElGamal: ElGamal,
    Algorithm.EllipticCurveElGamal: EllipticCurveElGamal,
    Algorithm.Paillier: Paillier,
    Algorithm.DamgardJurik: DamgardJurik,
    Algorithm.OkamotoUchiyama: OkamotoUchiyama,
    Algorithm.Benaloh: Benaloh,
    Algorithm.NaccacheStern: NaccacheStern,
    Algorithm.GoldwasserMicali: GoldwasserMicali,
    Algorithm.SanderYoungYung: SanderYoungYung,
    Algorithm.BonehGohNissim: BonehGohNissim,
}


def validate_keys(algorithm_name: str, keys: dict) -> None:
    """
    Validate that user-supplied keys carry the required sub-fields for the
    given cryptosystem. `public_key` is always required (every cryptosystem
    needs it for encryption); `private_key` is optional (absent in
    encryption-only setups). Whichever is present must contain all its
    required sub-fields.

    The required-field spec is read from the cryptosystem class's
    `REQUIRED_KEYS` attribute (a dict with "public_key", "private_key", and
    an optional "nested" entry for dict-valued public_key sub-fields).

    Args:
        algorithm_name (str): user-facing algorithm name (e.g. "RSA")
        keys (dict): user-supplied keys dict
    Raises:
        ValueError: when required fields are missing or structure is wrong
    """
    cls = _ALGORITHM_TO_CLASS.get(algorithm_name)
    if cls is None:
        return
    spec = cls.REQUIRED_KEYS

    if not isinstance(keys, dict):
        raise ValueError(
            f"{algorithm_name} keys must be a dict, got {type(keys).__name__}"
        )

    if "public_key" not in keys:
        raise ValueError(f"{algorithm_name} keys must contain 'public_key'")

    for kind in ("public_key", "private_key"):
        if kind not in keys:
            continue
        if not isinstance(keys[kind], dict):
            raise ValueError(
                f"{algorithm_name} '{kind}' must be a dict, "
                f"got {type(keys[kind]).__name__}"
            )
        missing = [f for f in spec[kind] if f not in keys[kind]]
        if missing:
            raise ValueError(
                f"{algorithm_name} '{kind}' is missing required fields: {missing}"
            )

    nested = spec.get("nested") or {}
    for parent, required in nested.items():
        if "public_key" not in keys or parent not in keys["public_key"]:
            continue
        sub = keys["public_key"][parent]
        if not isinstance(sub, dict):
            raise ValueError(
                f"{algorithm_name} 'public_key.{parent}' must be a dict, "
                f"got {type(sub).__name__}"
            )
        missing = [f for f in required if f not in sub]
        if missing:
            raise ValueError(
                f"{algorithm_name} 'public_key.{parent}' is missing required "
                f"fields: {missing}"
            )
