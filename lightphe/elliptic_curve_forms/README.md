# Elliptic Curve Cryptography

Building an elliptic curve with LightPHE is very straightforward.

```python
# import required forms
from lightphe.elliptic_curve_forms.weierstrass import Weierstrass
from lightphe.elliptic_curve_forms.edwards import TwistedEdwards
from lightphe.elliptic_curve_forms.koblitz import Koblitz

# build a default Edwards curve
curve = TwistedEdwards()

# or build an Edwards curve with custom curve configuration
# curve = TwistedEdwards(curve = "ed25519")
```

Once the curve is initialized in one of Weierstrass, Edwards or Koblitz forms, you can perform operations such as point addition, doubling, and scalar multiplication.

```python
# Base Point
G = curve.G
assert curve.is_on_curve(G) is True
 
_2G = curve.double_point(G)
# _2G = curve.add_points(G, G)
assert curve.is_on_curve(_2G) is True
 
_3G = curve.add_points(G, _2G)
assert curve.is_on_curve(_2G) is True
 
_2025G = curve.double_and_add(G, k=2025)
assert curve.is_on_curve(_2025G) is True
```

When creating a LightPHE object, if the algorithm is set to EllipticCurve-ElGamal, you can optionally specify the elliptic curve's form and its specific name. By default, the form is Weierstrass, and the curve is secp256k1.

```python
phe = LightPHE(
    algorithm_name="EllipticCurve-ElGamal",
    form="edwards",
    curve="ed25519",
)
```

Below is a list of elliptic curves supported by LightPHE. Each curve has a specific order (n), which defines the number of points in the finite field. The order directly impacts the cryptosystem's security strength. A higher order typically corresponds to a stronger cryptosystem, making it more resistant to cryptographic attacks.

## Edwards Curves

| form | curve | field | n (bits) |
| --- | --- | --- | --- |
| edwards | e521 | prime | 519 |
| edwards | id-tc26-gost-3410-2012-512-paramsetc | prime | 510 |
| edwards | numsp512t1 | prime | 510 |
| edwards | ed448 | prime | 446 |
| edwards | curve41417 | prime | 411 |
| edwards | numsp384t1 | prime | 382 |
| edwards | id-tc26-gost-3410-2012-256-paramseta | prime | 255 |
| edwards | ed25519 | prime | 254 |
| edwards | mdc201601 | prime | 254 |
| edwards | numsp256t1 | prime | 254 |
| edwards | jubjub | prime | 252 |

## Elliptic Curves in Weierstass Form

| form | curve | field | n (bits) |
| --- | --- | --- | --- |
| weierstrass | bn638 | prime | 638 |
| weierstrass | bn606 | prime | 606 |
| weierstrass | bn574 | prime | 574 |
| weierstrass | bn542 | prime | 542 |
| weierstrass | p521 | prime | 521 |
| weierstrass | brainpoolp512r1 | prime | 512 |
| weierstrass | brainpoolp512t1 | prime | 512 |
| weierstrass | fp512bn | prime | 512 |
| weierstrass | numsp512d1 | prime | 512 |
| weierstrass | gost512 | prime | 511 |
| weierstrass | bn510 | prime | 510 |
| weierstrass | bn478 | prime | 478 |
| weierstrass | bn446 | prime | 446 |
| weierstrass | bls12-638 | prime | 427 |
| weierstrass | bn414 | prime | 414 |
| weierstrass | brainpoolp384r1 | prime | 384 |
| weierstrass | brainpoolp384t1 | prime | 384 |
| weierstrass | fp384bn | prime | 384 |
| weierstrass | numsp384d1 | prime | 384 |
| weierstrass | p384 | prime | 384 |
| weierstrass | bls24-477 | prime | 383 |
| weierstrass | bn382 | prime | 382 |
| weierstrass | curve67254 | prime | 380 |
| weierstrass | bn350 | prime | 350 |
| weierstrass | brainpoolp320r1 | prime | 320 |
| weierstrass | brainpoolp320t1 | prime | 320 |
| weierstrass | bn318 | prime | 318 |
| weierstrass | bls12-455 | prime | 305 |
| weierstrass | bls12-446 | prime | 299 |
| weierstrass | bn286 | prime | 286 |
| weierstrass | brainpoolp256r1 | prime | 256 |
| weierstrass | brainpoolp256t1 | prime | 256 |
| weierstrass | fp256bn | prime | 256 |
| weierstrass | gost256 | prime | 256 |
| weierstrass | numsp256d1 | prime | 256 |
| weierstrass | p256 | prime | 256 |
| weierstrass | secp256k1 | prime | 256 |
| weierstrass | tom256 | prime | 256 |
| weierstrass | bls12-381 | prime | 255 |
| weierstrass | pallas | prime | 255 |
| weierstrass | tweedledee | prime | 255 |
| weierstrass | tweedledum | prime | 255 |
| weierstrass | vesta | prime | 255 |
| weierstrass | bn254 | prime | 254 |
| weierstrass | fp254bna | prime | 254 |
| weierstrass | fp254bnb | prime | 254 |
| weierstrass | bls12-377 | prime | 253 |
| weierstrass | curve1174 | prime | 249 |
| weierstrass | mnt4 | prime | 240 |
| weierstrass | mnt5-1 | prime | 240 |
| weierstrass | mnt5-2 | prime | 240 |
| weierstrass | mnt5-3 | prime | 240 |
| weierstrass | prime239v1 | prime | 239 |
| weierstrass | prime239v2 | prime | 239 |
| weierstrass | prime239v3 | prime | 239 |
| weierstrass | secp224k1 | prime | 225 |
| weierstrass | brainpoolp224r1 | prime | 224 |
| weierstrass | brainpoolp224t1 | prime | 224 |
| weierstrass | curve4417 | prime | 224 |
| weierstrass | fp224bn | prime | 224 |
| weierstrass | p224 | prime | 224 |
| weierstrass | bn222 | prime | 222 |
| weierstrass | curve22103 | prime | 218 |
| weierstrass | brainpoolp192r1 | prime | 192 |
| weierstrass | brainpoolp192t1 | prime | 192 |
| weierstrass | p192 | prime | 192 |
| weierstrass | prime192v2 | prime | 192 |
| weierstrass | prime192v3 | prime | 192 |
| weierstrass | secp192k1 | prime | 192 |
| weierstrass | bn190 | prime | 190 |
| weierstrass | secp160k1 | prime | 161 |
| weierstrass | secp160r1 | prime | 161 |
| weierstrass | secp160r2 | prime | 161 |
| weierstrass | brainpoolp160r1 | prime | 160 |
| weierstrass | brainpoolp160t1 | prime | 160 |
| weierstrass | mnt3-1 | prime | 160 |
| weierstrass | mnt3-2 | prime | 160 |
| weierstrass | mnt3-3 | prime | 160 |
| weierstrass | mnt2-1 | prime | 159 |
| weierstrass | mnt2-2 | prime | 159 |
| weierstrass | bn158 | prime | 158 |
| weierstrass | mnt1 | prime | 156 |
| weierstrass | secp128r1 | prime | 128 |
| weierstrass | secp128r2 | prime | 126 |
| weierstrass | secp112r1 | prime | 112 |
| weierstrass | secp112r2 | prime | 110 |

## Koblitz Curves

| form | curve | field | n (bits) |
| --- | --- | --- | --- |
| koblitz | b571 | binary | 570 |
| koblitz | k571 | binary | 570 |
| koblitz | c2tnb431r1 | binary | 418 |
| koblitz | b409 | binary | 409 |
| koblitz | k409 | binary | 407 |
| koblitz | c2pnb368w1 | binary | 353 |
| koblitz | c2tnb359v1 | binary | 353 |
| koblitz | c2pnb304w1 | binary | 289 |
| koblitz | b283 | binary | 282 |
| koblitz | k283 | binary | 281 |
| koblitz | c2pnb272w1 | binary | 257 |
| koblitz | ansit239k1 | binary | 238 |
| koblitz | c2tnb239v1 | binary | 238 |
| koblitz | c2tnb239v2 | binary | 237 |
| koblitz | c2tnb239v3 | binary | 236 |
| koblitz | b233 | binary | 233 |
| koblitz | k233 | binary | 232 |
| koblitz | ansit193r1 | binary | 193 |
| koblitz | ansit193r2 | binary | 193 |
| koblitz | c2pnb208w1 | binary | 193 |
| koblitz | c2tnb191v1 | binary | 191 |
| koblitz | c2tnb191v2 | binary | 190 |
| koblitz | c2tnb191v3 | binary | 189 |
| koblitz | b163 | binary | 163 |
| koblitz | c2pnb163v1 | binary | 163 |
| koblitz | k163 | binary | 163 |
| koblitz | ansit163r1 | binary | 162 |
| koblitz | c2pnb163v2 | binary | 162 |
| koblitz | c2pnb163v3 | binary | 162 |
| koblitz | c2pnb176w1 | binary | 161 |
| koblitz | sect131r1 | binary | 131 |
| koblitz | sect131r2 | binary | 131 |
| koblitz | sect113r1 | binary | 113 |
| koblitz | sect113r2 | binary | 113 |
| koblitz | wap-wsg-idm-ecid-wtls1 | binary | 112 |
