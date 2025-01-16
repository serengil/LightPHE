# LightPHE

<div align="center">

[![PyPI Downloads](https://static.pepy.tech/personalized-badge/lightphe?period=total&units=international_system&left_color=grey&right_color=blue&left_text=downloads)](https://pepy.tech/project/lightphe)
[![Stars](https://img.shields.io/github/stars/serengil/LightPHE?color=yellow&style=flat&label=%E2%AD%90%20stars)](https://github.com/serengil/LightPHE/stargazers)
[![Tests](https://github.com/serengil/LightPHE/actions/workflows/tests.yml/badge.svg)](https://github.com/serengil/LightPHE/actions/workflows/tests.yml)
[![License](http://img.shields.io/:license-MIT-green.svg?style=flat)](https://github.com/serengil/LightPHE/blob/master/LICENSE)
[![DOI](http://img.shields.io/:DOI-10.48550/arXiv.2408.05219-blue.svg?style=flat)](https://arxiv.org/abs/2408.05219)

[![Blog](https://img.shields.io/:blog-sefiks.com-blue.svg?style=flat&logo=wordpress)](https://sefiks.com)
[![YouTube](https://img.shields.io/:youtube-@sefiks-red.svg?style=flat&logo=youtube)](https://www.youtube.com/@sefiks?sub_confirmation=1)
[![Twitter](https://img.shields.io/:follow-@serengil-blue.svg?style=flat&logo=x)](https://twitter.com/intent/user?screen_name=serengil)

[![Support me on Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.vercel.app%2Fapi%3Fusername%3Dserengil%26type%3Dpatrons&style=flat)](https://www.patreon.com/serengil?repo=lightphe)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/serengil?logo=GitHub&color=lightgray)](https://github.com/sponsors/serengil)
[![Buy Me a Coffee](https://img.shields.io/badge/-buy_me_a%C2%A0coffee-gray?logo=buy-me-a-coffee)](https://buymeacoffee.com/serengil)

</div>

<p align="center"><img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/phi.png" width="200" height="240"></p>

LightPHE is a lightweight partially homomorphic encryption library for python. It is a hybrid homomoprhic encryption library wrapping many schemes such as [`RSA`](https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/), [`ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/), [`Exponential ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/), [`Elliptic Curve ElGamal`](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/) ([`Weierstrass`](https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/), [`Koblitz`](sefiks.com/2016/03/13/the-math-behind-elliptic-curves-over-binary-field/) and [`Edwards`](https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/) forms), [`Paillier`](https://sefiks.com/2023/04/03/a-step-by-step-partially-homomorphic-encryption-example-with-paillier-in-python/), [`Damgard-Jurik`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/), [`Okamoto–Uchiyama`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-okamoto-uchiyama-in-python/), [`Benaloh`](https://sefiks.com/2023/10/06/a-step-by-step-partially-homomorphic-encryption-example-with-benaloh-in-python-from-scratch/), [`Naccache–Stern`](https://sefiks.com/2023/10/26/a-step-by-step-partially-homomorphic-encryption-example-with-naccache-stern-in-python/), [`Goldwasser–Micali`](https://sefiks.com/2023/10/27/a-step-by-step-partially-homomorphic-encryption-example-with-goldwasser-micali-in-python/).

# Partially vs Fully Homomorphic Encryption

Even though fully homomorphic encryption (FHE) has become available in recent times, but when considering the trade-offs, LightPHE emerges as a more efficient and practical choice. If your specific task doesn't demand the full homomorphic capabilities, opting for partial homomorphism with LightPHE is the logical decision.

- 🏎️ Notably faster
- 💻 Demands fewer computational resources
- 📏 Generating much smaller ciphertexts
- 🔑 Distributing much smaller keys
- 🧠 Well-suited for memory-constrained environments
- ⚖️ Strikes a favorable balance for practical use cases

# Installation [![PyPI](https://img.shields.io/pypi/v/lightphe.svg)](https://pypi.org/project/lightphe/)

The easiest way to install the LightPHE package is to install it from python package index (PyPI).

```shell
pip install lightphe
```

Then you will be able to import the library and use its functionalities.

```python
from lightphe import LightPHE
```

# Summary of Homomorphic Features of Different Cryptosystems in LightPHE

In summary, LightPHE is covering following algorithms and these are partially homomorphic with respect to the operations mentioned in the following table.

| Algorithm | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Multiplication with a Plain Constant | Exclusively<br>Homomorphic | Regeneration<br>of Ciphertext |
| --- | --- | --- | --- | --- | --- |
| RSA | ✅ | ❌ | ❌ | ❌ | ❌ |
| ElGamal | ✅ | ❌ | ❌ | ❌ | ✅ |
| Exponential ElGamal | ❌ | ✅ | ✅ | ❌ | ✅ |
| Elliptic Curve ElGamal | ❌ | ✅ | ✅ | ❌ | ❌ |
| Paillier | ❌ | ✅ | ✅ | ❌ | ✅ |
| Damgard-Jurik | ❌ | ✅ | ✅ | ❌ | ✅ |
| Benaloh | ❌ | ✅ | ✅ | ❌ | ✅ |
| Naccache-Stern | ❌ | ✅ | ✅ | ❌ | ✅ |
| Okamoto-Uchiyama | ❌ | ✅ | ✅ | ❌ | ✅ |
| Goldwasser-Micali | ❌ | ❌ | ❌ | ✅ | ❌ |

# Building cryptosystem

Once you imported the library, then you can build a cryptosystem for several algorithms. This basically generates private and public key pair.

```python
algorithms = [
  "RSA",
  "ElGamal",
  "Exponential-ElGamal",
  "Paillier",
  "Damgard-Jurik",
  "Okamoto-Uchiyama",
  "Benaloh",
  "Naccache-Stern",
  "Goldwasser-Micali",
  "EllipticCurve-ElGamal"
]

phe = LightPHE(algorithm_name = algorithms[0])
```

# Encryption & Decryption

Once you built your cryptosystem, you will be able to encrypt and decrypt messages with the built cryptosystem.

```python
# define plaintext
m = 17

# calculate ciphertext
c = phe.encrypt(m)

# proof of work
assert phe.decrypt(c) == m
```

# Homomorphic Operations

Once you have the ciphertext, you will be able to perform homomorphic operations on encrypted data without holding private key. For instance, Paillier is homomorphic with respect to the addition. In other words, decryption of the addition of two ciphertexts is equivalent to addition of plaintexts.

### On-Prem Encryption

This code snippet illustrates how to generate a random public-private key pair using the Paillier and encrypt a plaintext pair. The resulting ciphertext pair, c1 and c2, along with the public key, is then sent from the on-premises environment to the cloud.

```python
def on_premise() -> Tuple[int, int, dict]:
    """
    Executes on-premise operations: initializes a cryptosystem by generating 
    a random public-private key pair, then encrypts two plaintext values.

    Returns:
       result (tuple): A tuple containing:
       - c1 (int): The first ciphertext
       - c2 (int): The second ciphertext
       - public_key (dict): The public key for the cryptosystem
    """
    # generate a random private-public key pair
    phe = LightPHE(algorithm_name = "Paillier")

    # define plaintexts
    m1 = 10000 # base salary in usd
    m2 = 500 # wage increase in usd

    # calculate ciphertexts
    c1 = phe.encrypt(m1).value
    c2 = phe.encrypt(m2).value

    return (c1, c2, phe.cs.public_key)
```

### Homomorphic Operations on Cloud

This code snippet demonstrates how to perform homomorphic addition on the cloud side without using the private key. However, the cloud is unable to decrypt c3 itself, even though it is the one that calculated it.

```python
def cloud(c1: int, c2: int, public_key: dict) -> int:
    """
    Performs cloud-side operations: reconstructs a cryptosystem using the 
    provided public key and executes a homomorphic addition on two ciphertexts.

    Args:
       c1 (int): The first ciphertext
       c2 (int): The second ciphertext
       public_key (dict): The public key of an existing cryptosystem
    Retunrs:
       c3 (int): The resulting ciphertext after homomorphic addition
    """
    # restore cryptosystem with just the public key
    phe = LightPHE(algorithm_name = "Paillier", keys = public_key)

    # cast c1 and c2 to ciphertext objects
    c1 = phe.create_ciphertext_obj(c1)
    c2 = phe.create_ciphertext_obj(c2)

    # confirm that cloud cannot decrypt c1
    with pytest.raises(ValueError, match="You must have private key"):
      phe.decrypt(c1)

    # confirm that cloud cannot decrypt c2
    with pytest.raises(ValueError, match="You must have private key"):
      phe.decrypt(c2)

    # perform homomorphic addition
    c3 = c1 + c2

    # confirm that cloud cannot decrypt c3
    with pytest.raises(ValueError, match="You must have private key"):
      phe.decrypt(c3)
    
    return c3.value
```

### On-Prem Decryption And Proof of Work

This code snippet demonstrates the proof of work. Even though c3 was calculated in the cloud by adding c1 and c2, on-premises can validate that its decryption must be equal to the addition of plaintexts m1 and m2.

```python
# proof of work - private key required
assert phe.decrypt(c3) == m1 + m2
```

In this homomorphic pipeline, the cloud's computational power was utilized to calculate c3, but it can only be decrypted by the on-premises side. Additionally, while we performed the encryption on the on-premises side, this is not strictly necessary; only the public key is required for encryption. Therefore, encryption can also be performed on the non-premises side. This approach is particularly convenient when collecting data from multiple edge devices and storing all of it in the cloud simultaneously.

### Scalar Multiplication

Besides, Paillier is supporting multiplying ciphertexts by a known plain constant. This code snippet demonstrates how to perform scalar multiplication on encrypted data using Paillier homomorphic encryption with the LightPHE library.

```python
# increasing something 5%
k = 1.05

# scalar multiplication - cloud (private key is not required)
c4 = k * c1

# proof of work on-prem - private key is required
assert phe.decrypt(c4) == k * m1
```

### Ciphertext Regeneration

Similar to the most of additively homomorphic algorithms, Paillier lets you to regenerate ciphertext while you are not breaking its plaintext restoration. You may consider to do this re-generation many times to have stronger ciphertexts.

```python
c1_prime = phe.regenerate_ciphertext(c1)
assert c1_prime.value != c1.value
assert phe.decrypt(c1_prime) == m1
assert phe.decrypt(c1) == m1
```

### Unsupported Operations

Finally, if you try to perform an operation that algorithm does not support, then an exception will be thrown. For instance, Paillier is not homomorphic with respect to the multiplication or xor. To put it simply, you cannot multiply two ciphertexts. If you enforce this calculation, you will have an exception.

```python
# pailier is not multiplicatively homomorphic
with pytest.raises(ValueError, match="Paillier is not homomorphic with respect to the multiplication"):
  c1 * c2

# pailier is not exclusively homomorphic
with pytest.raises(ValueError, match="Paillier is not homomorphic with respect to the exclusive or"):
  c1 ^ c2
```

However, if you tried to multiply ciphertexts with RSA, or xor ciphertexts with Goldwasser-Micali, these will be succeeded because those cryptosystems support those homomorphic operations.

### Elliptic Curve Cryptography

ECC is a powerful public-key cryptosystem based on the algebraic structure of elliptic curves over finite fields. In LightPHE, the [Elliptic Curve ElGamal](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/) scheme is implemented, offering a secure and efficient homomorphic encryption option. The library supports 100+ standard elliptic curves.

```python
some_curves = [
    {"form": "weierstrass", "curve": "secp256k1"},
    {"form": "edwards", "curve": "ed25519"},
    {"form": "koblitz", "curve": "k163"}
]

curve = some_curves[1]

phe = LightPHE(
    algorithm_name="EllipticCurve-ElGamal",
    form=curve["form"],
    curve=curve["curve"],
)
```

One of the crucial factors that define the security level of an elliptic curve cryptosystem is the order of the curve. The order of a curve is the number of points on the curve, and it directly influences the strength of the encryption. A higher order typically corresponds to a stronger cryptosystem, making it more resistant to cryptographic attacks.

Each curve in LightPHE has a specific order, which is carefully chosen to balance performance and security. By selecting an elliptic curve with a larger order, you increase the security of your cryptographic system, but this may come with a trade-off in computational efficiency. Therefore, choosing the appropriate curve order is a crucial decision based on your application’s security and performance requirements.

See [`Curves`](https://github.com/serengil/LightPHE/tree/master/lightphe/elliptic_curve_forms) page for more details.

# Contributing

All PRs are more than welcome! If you are planning to contribute a large patch, please create an issue first to get any upfront questions or design decisions out of the way first.

You should be able run `make test` and `make lint` commands successfully before committing. Once a PR is created, GitHub test workflow will be run automatically and unit test results will be available in [GitHub actions](https://github.com/serengil/LightPHE/actions/workflows/tests.yml) before approval. Besides, workflow will evaluate the code with pylint as well.

# Support

There are many ways to support a project - starring⭐️ the GitHub repo is just one 🙏

You can also support this work on [Patreon](https://www.patreon.com/serengil?repo=lightphe), [GitHub Sponsors](https://github.com/sponsors/serengil) or [Buy Me a Coffee](https://buymeacoffee.com/serengil).

<a href="https://www.patreon.com/serengil?repo=lightphe">
<img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/patreon.png" width="30%" height="30%">
</a>

<a href="https://buymeacoffee.com/serengil">
<img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/bmc-button.png" width="25%" height="25%">
</a>

Also, your company's logo will be shown on README on GitHub if you become sponsor in gold, silver or bronze tiers.

# Citation

Please cite LightPHE in your publications if it helps your research. Here is its BibTex entry:

```BibTeX
@misc{serengil2024lightphe,
   title     = {LightPHE: Integrating Partially Homomorphic Encryption into Python with Extensive Cloud Environment Evaluations}, 
   author    = {Serengil, Sefik Ilkin and Ozpinar, Alper},
   year      = {2024},
   publisher = {arXiv},
   url       = {https://arxiv.org/abs/2408.05219},
   doi       = {10.48550/arXiv.2408.05219}
}
```

Also, if you use LightPHE in your projects, please add `lightphe` in the `requirements.txt`.

# License

LightPHE is licensed under the MIT License - see [`LICENSE`](https://github.com/serengil/LightPHE/blob/master/LICENSE) for more details.
