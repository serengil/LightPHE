# LightPHE

<div align="center">

[![PyPI Downloads](https://static.pepy.tech/personalized-badge/lightphe?period=total&units=international_system&left_color=grey&right_color=blue&left_text=downloads)](https://pepy.tech/project/lightphe)
[![Stars](https://img.shields.io/github/stars/serengil/LightPHE?color=yellow&style=flat&label=%E2%AD%90%20stars)](https://github.com/serengil/LightPHE/stargazers)
[![Tests](https://github.com/serengil/LightPHE/actions/workflows/tests.yml/badge.svg)](https://github.com/serengil/LightPHE/actions/workflows/tests.yml)
[![License](http://img.shields.io/:license-MIT-green.svg?style=flat)](https://github.com/serengil/LightPHE/blob/master/LICENSE)
[![arXiv](https://img.shields.io/badge/arXiv-2408.05219-b31b1b.svg?logo=arXiv)](https://arxiv.org/abs/2408.05219)

[![Blog](https://img.shields.io/:blog-sefiks.com-blue.svg?style=flat&logo=wordpress)](https://sefiks.com)
[![YouTube](https://img.shields.io/:youtube-@sefiks-red.svg?style=flat&logo=youtube)](https://www.youtube.com/@sefiks?sub_confirmation=1)
[![Twitter](https://img.shields.io/:follow-@serengil-blue.svg?style=flat&logo=x)](https://twitter.com/intent/user?screen_name=serengil)

[![Patreon](https://img.shields.io/:become-patron-f96854.svg?style=flat&logo=patreon)](https://www.patreon.com/serengil?repo=lightphe)
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

| Algorithm | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Exclusively<br>Homomorphic | Regeneration<br>of Ciphertext |
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

cs = LightPHE(algorithm_name = algorithms[0])
```

# Homomorphic Operations

The following example demonstrates a simple workflow using LightPHE with an additively homomorphic cryptosystem (e.g. Paillier). First, we build the cryptosystem on-premises and define two plaintext values. Next, we encrypt the plaintexts, which can be done either on-premises or in the cloud, and does not require the private key. Homomorphic operations, such as addition and scalar multiplication, can then be performed on the ciphertexts—these operations can be offloaded to the cloud, leveraging its computational power without revealing the private key or the plaintext. Finally, the results are decrypted on-premises using the private key, verifying that the homomorphic operations on encrypted data produce the expected plaintext results.

```python
# build an additively homomorphic cryptosystem
cs = LightPHE(algorithm_name = "Paillier")

# define plaintexts
m1 = 10000 # base salary in usd
m2 = 500 # wage increase in usd

# encrypt plaintexts - private key is not required.
c1 = cs.encrypt(m1)
c2 = cs.encrypt(m2)

# homomorphic addition - private key is not required
c3 = c1 + c2

# homomorphic scalar multiplication - private key is not required
k = 1.05 # increase something 5%
c4 = k * c1

# decryption - private key is required
assert cs.decrypt(c3) == m1 + m2
assert cs.decrypt(c4) == k * m1
```

On the other hand, if you adopt a multiplicatively homomorphic cryptosystem (e.g. RSA or ElGamal), you can multiply ciphertexts without revealing the private key or the plaintext.

```python
# build a multiplicatively homomorphic cryptosystem
cs = LightPHE(algorithm_name = "RSA")

# define plaintexts
m1 = 17
m2 = 21

# encrypt plaintexts - private key is not required.
c1 = cs.encrypt(m1)
c2 = cs.encrypt(m2)

# homomorphic multiplication
c3 = c1 * c2

# decryption - private key is required
assert cs.decrypt(c3) == m1 * m2
```

### Ciphertext Regeneration

The most of additively homomorphic algorithms allow you to regenerate ciphertext while you are not breaking its plaintext restoration. You may consider to do this re-generation many times to have stronger ciphertexts.

```python
c1_prime = cs.regenerate_ciphertext(c1)
assert c1_prime.value != c1.value
assert cs.decrypt(c1_prime) == m1
assert cs.decrypt(c1) == m1
```

### Elliptic Curve Cryptography

ECC is a powerful public-key cryptosystem based on the algebraic structure of elliptic curves over finite fields. The library supports 3 elliptic curve forms (weierstrass (default), edwards and koblitz) and 100+ standard elliptic curve configurations.

In LightPHE, the [Elliptic Curve ElGamal](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/) scheme is implemented, offering a secure and efficient homomorphic encryption option.

```python
forms = ["weierstrass", "edwards", "koblitz"]
phe = LightPHE(
    algorithm_name="EllipticCurve-ElGamal",
    form="edwards",
    # curve="ed448", # optinally you can specify the curve for given form
)
```

One of the crucial factors that define the security level of an elliptic curve cryptosystem is the order of the curve. The order of a curve is the number of points on the curve, and it directly influences the strength of the encryption. A higher order typically corresponds to a stronger cryptosystem, making it more resistant to cryptographic attacks.

Each curve in LightPHE has a specific order, which is carefully chosen to balance performance and security. By selecting an elliptic curve with a larger order, you increase the security of your cryptographic system, but this may come with a trade-off in computational efficiency. Therefore, choosing the appropriate curve order is a crucial decision based on your application’s security and performance requirements.

See [`curves`](https://github.com/serengil/LightECC#supported-curves) page for a list of all supported forms, curves and their details.

### Vector Embeddings

LightPHE supports homomorphic encryption on vector embeddings. This is useful in privacy-preserving machine learning, secure aggregation, and confidential data processing.

```python
# build an additively homomorphic cryptosystem (e.g. Paillier)
cs = LightPHE("Paillier")

# define plain embeddings
t1 = [1.005, 2.05, 3.6, 4, 4.02, 3.5]
t2 = [5, 6.2, 7.5, 8.02, 8.02, 4.5]
t3 = [1.03, 2.04, 3.05, 7.02, 2.01, 1.06]

# encrypt embeddings
c1, c2 = cs.encrypt(t1), cs.encrypt(t2)

# perform addition of two encrypted embeddings
c4 = c1 + c2

# perform scalar multiplication on an embedding
c5 = 3 * c1

# perform element-wise multiplication between an encrypted embedding and plain embedding
c6 = c1 * t3

# encrypted dot product (likewise cosine similarity)
c7 = c1 @ t3

# proof of work
assert np.allclose(cs.decrypt(c4), [a + b for a, b in zip(t1, t2)], rtol=1e-2)
assert np.allclose(cs.decrypt(c5), [a * 3 for a in t1], rtol=1e-2)
assert np.allclose(cs.decrypt(c6), [a * b for a, b in zip(t1, t3)], rtol=1e-2)
assert np.allclose(cs.decrypt(c7)[0], sum([a * b for a, b in zip(t1, t3)]), rtol=1e-2)
```

# Contributing

All PRs are more than welcome! If you are planning to contribute a large patch, please create an issue first to get any upfront questions or design decisions out of the way first.

You should be able run `make test` and `make lint` commands successfully before committing. Once a PR is created, GitHub test workflow will be run automatically and unit test results will be available in [GitHub actions](https://github.com/serengil/LightPHE/actions/workflows/tests.yml) before approval.

# Support

There are many ways to support a project - starring⭐️ the GitHub repo is just one 🙏

You can also support this work on [Patreon](https://www.patreon.com/serengil?repo=lightphe), [GitHub Sponsors](https://github.com/sponsors/serengil) or [Buy Me a Coffee](https://buymeacoffee.com/serengil).

<a href="https://www.patreon.com/serengil?repo=lightphe">
<img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/patreon.png" width="30%">
</a>

<a href="https://buymeacoffee.com/serengil">
<img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/bmc-button.png" width="25%">
</a>

Also, your company's logo will be shown on README on GitHub if you become sponsor in gold, silver or bronze tiers.

# Citation

Please cite LightPHE in your publications if it helps your research. Here is its BibTex entry:

```BibTeX
@article{serengil2024lightphe,
  title={LightPHE: Integrating Partially Homomorphic Encryption into Python with Extensive Cloud Environment Evaluations},
  author={Serengil, Sefik Ilkin and Ozpinar, Alper},
  journal={arXiv preprint arXiv:2408.05219},
  note={doi: 10.48550/arXiv.2408.05219. [Online]. Available: \url{https://arxiv.org/abs/2408.05219}},
  year={2025}
}
```

```BibTeX
@article{serengil2025vectorsimilarity,
  title={Encrypted Vector Similarity Computations Using Partially Homomorphic Encryption: Applications and Performance Analysis},
  author={Serengil, Sefik and Ozpinar, Alper},
  journal={arXiv preprint arXiv:2503.05850},
  note={doi: 10.48550/arXiv.2503.05850. [Online]. Available: \url{https://arxiv.org/abs/2503.05850}},
  year={2025}
}
```

Also, if you use LightPHE in your projects, please add `lightphe` in the `requirements.txt`.

# License

LightPHE is licensed under the MIT License - see [`LICENSE`](https://github.com/serengil/LightPHE/blob/master/LICENSE) for more details.
