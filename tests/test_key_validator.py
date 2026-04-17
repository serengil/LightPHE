import copy

import pytest

from lightphe import LightPHE
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_key_validator.py")


ALGORITHMS = [
    ("RSA", 50),
    ("ElGamal", 50),
    ("Exponential-ElGamal", 50),
    ("EllipticCurve-ElGamal", 50),
    ("Paillier", 50),
    ("Damgard-Jurik", 50),
    ("Okamoto-Uchiyama", 50),
    ("Benaloh", 50),
    ("Naccache-Stern", 50),
    ("Goldwasser-Micali", 50),
    ("Sander-Young-Yung", 50),
    ("Boneh-Goh-Nissim", 50),
]


@pytest.mark.parametrize("algorithm_name,key_size", ALGORITHMS)
def test_missing_public_key_field_is_rejected(algorithm_name, key_size):
    """Dropping a required public_key sub-field must raise ValueError."""
    cs = LightPHE(algorithm_name=algorithm_name, key_size=key_size, max_tries=10000)
    field = cs.cs.REQUIRED_KEYS["public_key"][0]

    broken = copy.deepcopy(cs.cs.keys)
    del broken["public_key"][field]

    with pytest.raises(ValueError, match=f"missing required fields.*{field}"):
        LightPHE(algorithm_name=algorithm_name, keys=broken)

    logger.info(f"✅ {algorithm_name}: missing public_key.{field} rejected")


@pytest.mark.parametrize("algorithm_name,key_size", ALGORITHMS)
def test_missing_private_key_field_is_rejected(algorithm_name, key_size):
    """Dropping a required private_key sub-field must raise ValueError."""
    cs = LightPHE(algorithm_name=algorithm_name, key_size=key_size, max_tries=10000)
    field = cs.cs.REQUIRED_KEYS["private_key"][0]

    broken = copy.deepcopy(cs.cs.keys)
    del broken["private_key"][field]

    with pytest.raises(ValueError, match=f"missing required fields.*{field}"):
        LightPHE(algorithm_name=algorithm_name, keys=broken)

    logger.info(f"✅ {algorithm_name}: missing private_key.{field} rejected")


def test_missing_public_key_dict_is_rejected():
    """A keys dict without public_key must be rejected."""
    with pytest.raises(ValueError, match="must contain 'public_key'"):
        LightPHE(algorithm_name="RSA", keys={})


def test_private_key_only_is_rejected():
    """Supplying private_key without public_key must be rejected."""
    cs = LightPHE(algorithm_name="RSA", key_size=50)
    private_only = {"private_key": copy.deepcopy(cs.cs.keys["private_key"])}
    with pytest.raises(ValueError, match="must contain 'public_key'"):
        LightPHE(algorithm_name="RSA", keys=private_only)


def test_non_dict_keys_is_rejected():
    """A non-dict `keys` argument must be rejected."""
    with pytest.raises(ValueError, match="keys must be a dict"):
        LightPHE(algorithm_name="RSA", keys="not-a-dict")


def test_public_key_only_is_accepted():
    """Supplying only a full public_key must be accepted (encryption-only use)."""
    cs = LightPHE(algorithm_name="RSA", key_size=50)
    public_only = {"public_key": copy.deepcopy(cs.cs.keys["public_key"])}
    # should not raise
    LightPHE(algorithm_name="RSA", keys=public_only)


def test_bgn_nested_curve_field_is_rejected():
    """Dropping a required BGN curve sub-field must be rejected."""
    cs = LightPHE(algorithm_name="Boneh-Goh-Nissim", key_size=50, max_tries=10000)
    nested = cs.cs.REQUIRED_KEYS.get("nested", {}).get("curve", [])
    assert nested, "BGN must declare nested curve required fields"
    field = nested[0]

    broken = copy.deepcopy(cs.cs.keys)
    del broken["public_key"]["curve"][field]

    with pytest.raises(
        ValueError, match=rf"public_key\.curve.*missing required fields.*{field}"
    ):
        LightPHE(algorithm_name="Boneh-Goh-Nissim", keys=broken)

    logger.info(f"✅ BGN: missing public_key.curve.{field} rejected")
