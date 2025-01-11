# built-in dependencies
from typing import Union, Optional

# project dependencies
from lightphe.standard_curves import weierstrass, edwards, koblitz

CURVE_MAP = {
    "weierstrass": {
        None: weierstrass.Secp256k1,
        "secp256k1": weierstrass.Secp256k1,
        "p192": weierstrass.P192,
        "secp192r1": weierstrass.P192,
        "prime192v1": weierstrass.P192,
        "p224": weierstrass.P224,
        "secp224r1": weierstrass.P224,
        "wap-wsg-idm-ecid-wtls12": weierstrass.P224,
        "ansip224r1": weierstrass.P224,
        "p256": weierstrass.P256,
        "secp256r1": weierstrass.P256,
        "prime256v1": weierstrass.P256,
        "p384": weierstrass.P384,
        "secp384r1": weierstrass.P384,
        "ansip384r1": weierstrass.P384,
        "p521": weierstrass.P521,
        "secp521r1": weierstrass.P521,
        "ansip521r1": weierstrass.P521,
        "curve22103": weierstrass.Curve22103,
        "curve4417": weierstrass.Curve4417,
        "curve1174": weierstrass.Curve1174,
        "curve67254": weierstrass.Curve67254,
        "fp254bna": weierstrass.Fp254BNa,
        "fp254bnb": weierstrass.Fp254BNb,
        "fp224bn": weierstrass.Fp224BN,
        "fp256bn": weierstrass.Fp256BN,
        "fp384bn": weierstrass.Fp384BN,
        "fp512bn": weierstrass.Fp512BN,
        "tweedledum": weierstrass.Tweedledum,
        "tweedledee": weierstrass.Tweedledee,
        "pallas": weierstrass.Pallas,
        "vesta": weierstrass.Vesta,
        "tom256": weierstrass.Tom256,
        "numsp256d1": weierstrass.Numsp256d1,
        "numsp384d1": weierstrass.Numsp384d1,
        "numsp512d1": weierstrass.Numsp512d1,
        "brainpoolP160r1": weierstrass.BrainpoolP160r1,
        "brainpoolP160t1": weierstrass.BrainpoolP160t1,
        "brainpoolP192r1": weierstrass.BrainpoolP192r1,
        "brainpoolP192t1": weierstrass.BrainpoolP192t1,
        "brainpoolP224r1": weierstrass.BrainpoolP224r1,
        "brainpoolP224t1": weierstrass.BrainpoolP224t1,
        "brainpoolP256r1": weierstrass.BrainpoolP256r1,
        "brainpoolP256t1": weierstrass.BrainpoolP256t1,
        "brainpoolP320r1": weierstrass.BrainpoolP320r1,
        "brainpoolP320t1": weierstrass.BrainpoolP320t1,
        "brainpoolP384r1": weierstrass.BrainpoolP384r1,
        "brainpoolP384t1": weierstrass.BrainpoolP384t1,
        "brainpoolP512r1": weierstrass.BrainpoolP512r1,
        "brainpoolP512t1": weierstrass.BrainpoolP512t1,
        "mnt1": weierstrass.Mnt1,
        "mnt2/1": weierstrass.Mnt2_1,
        "mnt2/2": weierstrass.Mnt2_2,
        "mnt3/1": weierstrass.Mnt3_1,
        "mnt3/2": weierstrass.Mnt3_2,
        "mnt3/3": weierstrass.Mnt3_3,
        "mnt4": weierstrass.Mnt4,
        "mnt5/1": weierstrass.Mnt5_1,
        "mnt5/2": weierstrass.Mnt5_2,
        "mnt5/3": weierstrass.Mnt5_3,
        "prime192v2": weierstrass.Prime192v2,
        "prime192v3": weierstrass.Prime192v3,
        "prime239v1": weierstrass.Prime239v1,
        "prime239v2": weierstrass.Prime239v2,
        "prime239v3": weierstrass.Prime239v3,
        "bls12-377": weierstrass.Bls12_377,
        "bls12-381": weierstrass.Bls12_381,
        "bls12-446": weierstrass.Bls12_446,
        "bls12-455": weierstrass.Bls12_455,
        "bls12-638": weierstrass.Bls12_638,
        "bls24-477": weierstrass.Bls24_477,
        "gost256": weierstrass.Gost256,
        "gost512": weierstrass.Gost512,
        "bn158": weierstrass.Bn158,
        "bn190": weierstrass.Bn190,
        "bn222": weierstrass.Bn222,
        "bn254": weierstrass.Bn254,
        "bn286": weierstrass.Bn286,
        "bn318": weierstrass.Bn318,
        "bn350": weierstrass.Bn350,
        "bn382": weierstrass.Bn382,
        "bn414": weierstrass.Bn414,
        "bn446": weierstrass.Bn446,
        "bn478": weierstrass.Bn478,
        "bn510": weierstrass.Bn510,
        "bn542": weierstrass.Bn542,
        "bn574": weierstrass.Bn574,
        "bn606": weierstrass.Bn606,
        "bn638": weierstrass.Bn638,
        "secp112r1": weierstrass.Secp112r1,
        "secp112r2": weierstrass.Secp112r2,
        "secp128r1": weierstrass.Secp128r1,
        "secp128r2": weierstrass.Secp128r2,
        "secp160k1": weierstrass.Secp160k1,
        "secp160r1": weierstrass.Secp160r1,
        "secp160r2": weierstrass.Secp160r2,
        "secp192k1": weierstrass.Secp192k1,
        "secp224k1": weierstrass.Secp224k1,
    },
    "edwards": {
        None: edwards.Ed25519,
        "ed25519": edwards.Ed25519,
        "ed448": edwards.Ed448,
        "e521": edwards.E521,
        "curve41417": edwards.Curve41417,
        "jubjub": edwards.JubJub,
        "mdc201601": edwards.MDC201601,
        "numsp256d1": edwards.numsp256t1,
        "numsp384t1": edwards.numsp384t1,
        "numsp512t1": edwards.numsp512t1,
    },
    "koblitz": {
        None: koblitz.K409,
        "k163": koblitz.K163,
        "k233": koblitz.K233,
        "k283": koblitz.K283,
        "k409": koblitz.K409,
        "k571": koblitz.K571,
    },
}


def build_curve(form_name: str, curve_name: Optional[str] = None) -> Union[
    weierstrass.WeierstrassInterface,
    edwards.TwistedEdwardsInterface,
    koblitz.KoblitzInterface,
]:
    """
    Builds a curve arguments based on the form and curve name
    Args:
        form_name (str): curve form name
        curve_name (str): curve name
    Returns:
        curve_args (WeierstrassInterface or TwistedEdwardsInterface): curve arguments
    """
    if form_name not in CURVE_MAP:
        raise ValueError(f"Unsupported curve form - {form_name}")

    if curve_name not in CURVE_MAP[form_name]:
        raise ValueError(f"Unsupported {form_name} curve - {curve_name}")

    return CURVE_MAP[form_name][curve_name]()
