# LightPHE

<div align="center">

[![PyPI Downloads](https://static.pepy.tech/personalized-badge/lightphe?period=total&units=international_system&left_color=grey&right_color=blue&left_text=pypi%20downloads)](https://pepy.tech/project/lightphe)
[![Stars](https://img.shields.io/github/stars/serengil/LightPHE?color=yellow&style=flat&label=%E2%AD%90%20stars)](https://github.com/serengil/LightPHE/stargazers)
[![Tests](https://github.com/serengil/LightPHE/actions/workflows/tests.yml/badge.svg)](https://github.com/serengil/LightPHE/actions/workflows/tests.yml)
[![License](http://img.shields.io/:license-MIT-green.svg?style=flat)](https://github.com/serengil/LightPHE/blob/master/LICENSE)
[![Support me on Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.vercel.app%2Fapi%3Fusername%3Dserengil%26type%3Dpatrons&style=flat)](https://www.patreon.com/serengil?repo=lightphe)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/serengil?logo=GitHub&color=lightgray)](https://github.com/sponsors/serengil)

[![Blog](https://img.shields.io/:blog-sefiks.com-blue.svg?style=flat&logo=wordpress)](https://sefiks.com)
[![YouTube](https://img.shields.io/:youtube-@sefiks-red.svg?style=flat&logo=youtube)](https://www.youtube.com/@sefiks?sub_confirmation=1)
[![Twitter](https://img.shields.io/:follow-@serengil-blue.svg?style=flat&logo=twitter)](https://twitter.com/intent/user?screen_name=serengil)

</div>

<p align="center"><img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/phi.png" width="200" height="240"></p>

LightPHE is a lightweight partially homomorphic encryption library for python. It is a hybrid homomoprhic encryption library wrapping many schemes such as [`RSA`](https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/), [`ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/), [`Exponential ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/), [`Elliptic Curve ElGamal`](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/), [`Paillier`](https://sefiks.com/2023/04/03/a-step-by-step-partially-homomorphic-encryption-example-with-paillier-in-python/), [`Damgard-Jurik`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/), [`Okamoto–Uchiyama`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-okamoto-uchiyama-in-python/), [`Benaloh`](https://sefiks.com/2023/10/06/a-step-by-step-partially-homomorphic-encryption-example-with-benaloh-in-python-from-scratch/), [`Naccache–Stern`](https://sefiks.com/2023/10/26/a-step-by-step-partially-homomorphic-encryption-example-with-naccache-stern-in-python/), [`Goldwasser–Micali`](https://sefiks.com/2023/10/27/a-step-by-step-partially-homomorphic-encryption-example-with-goldwasser-micali-in-python/).

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

cs = LightPHE(algorithm_name = algorithms[0])
```

# Encryption & Decryption

Once you built your cryptosystem, you will be able to encrypt and decrypt messages with the built cryptosystem.

```python
# define plaintext
m = 17

# calculate ciphertext
c = cs.encrypt(m)

assert cs.decrypt(c) == m
```

# Homomorphic Operations

Once you have the ciphertext, you will be able to perform homomorphic operations on encrypted data. For instance, Paillier is homomorphic with respect to the addition. In other words, decryption of the addition of two ciphertexts is equivalent to addition of plaintexts. 

```python
cs = LightPHE(algorithm_name = "Paillier")

# define plaintexts
m1 = 17
m2 = 23

# calculate ciphertexts
c1 = cs.encrypt(m1)
c2 = cs.encrypt(m2)

# homomorphic addition - private key is not required!
c3 = c1 + c2

# proof of work
assert cs.decrypt(c3) == m1 + m2
```

⚡ Notice that once can perform `c1 + c2` here without holding private key. However, just the data owner with private key can perform encryption and decryption. This is the basic definition of homomorphic encryption.

Besides, Paillier is supporting multiplying ciphertexts by a known plain constant. Simply put, decryption of scalar multiplication of ciphertext is equivalent to that constant times plaintext as well. 

```python
# increasing something 5%
k = 1.05

# scalar multiplication - private key is not required!
c4 = k * c1

# proof of work
assert cs.decrypt(c4) == k * m1
```

⚡ Herein, `k * c1` operation can be performed by anyone without holding private key.

Similar to the most of additively homomorphic algorithms, Paillier lets you to regenerate ciphertext while you are not breaking its plaintext restoration. You may consider to do this re-generation many times to have stronger ciphertexts.

```python
c1_prime = cs.regenerate_ciphertext(c1)
assert c1_prime.value != c1.value
assert cs.decrypt(c1_prime) == m1
assert cs.decrypt(c1) == m1
```

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

# Working with vectors

You can encrypt the output vectors of machine learning models with LightPHE. These encrypted tensors come with homomorphic operation support including homomorphic addition, element-wise multiplication and scalar multiplication.

```python
# build an additively homomorphic cryptosystem
cs = LightPHE(algorithm_name="Paillier")

# define plain tensors
t1 = [1.005, 2.05, 3.5, 4]
t2 = [5, 6.2, 7.002, 8.02]

# encrypt tensors
c1 = cs.encrypt(t1)
c2 = cs.encrypt(t2)

# perform homomorphic addition
c3 = c1 + c2

# perform homomorphic element-wise multiplication
c4 = c1 * c2

# perform homomorphic scalar multiplication
k = 5
c5 = k * c1

# decrypt the addition tensor
t3 = cs.decrypt(c3)

# decrypt the element-wise multiplied tensor
t4 = cs.decrypt(c4)

# decrypt the scalar multiplied tensor
t5 = cs.decrypt(c5)

# data validations
threshold = 0.5
for i in range(0, len(t1)):
   assert abs((t1[i] + t2[i]) - t3[i]) < threshold
   assert abs((t1[i] * t2[i]) - t4[i]) < threshold
   assert abs((t1[i] * k) - t5[i]) < threshold
```

Unfortunately, vector multiplication (dot product) requires both homomorphic addition and homomorphic multiplication and this cannot be done with partially homomorphic encryption algorithms.

# Contributing

All PRs are more than welcome! If you are planning to contribute a large patch, please create an issue first to get any upfront questions or design decisions out of the way first.

You should be able run `make test` and `make lint` commands successfully before committing. Once a PR is created, GitHub test workflow will be run automatically and unit test results will be available in [GitHub actions](https://github.com/serengil/LightPHE/actions/workflows/tests.yml) before approval. Besides, workflow will evaluate the code with pylint as well.

# Support

There are many ways to support a project - starring⭐️ the GitHub repo is just one 🙏

You can also support this work on [Patreon](https://www.patreon.com/serengil?repo=lightphe) or [GitHub Sponsors](https://github.com/sponsors/serengil).

<a href="https://www.patreon.com/serengil?repo=lightphe">
<img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/patreon.png" width="30%" height="30%">
</a>

# Citation

Please cite LightPHE in your publications if it helps your research. Here is its BibTex entry:

```BibTeX
@misc{serengil2023lightphe,
  abstract     = {A Lightweight Partially Homomorphic Encryption Library for Python},
  author       = {Serengil, Sefik Ilkin},
  title        = {LightPHE},
  howpublished = {https://github.com/serengil/LightPHE},
  year         = {2023}
}
```

Also, if you use LightPHE in your projects, please add `lightphe` in the `requirements.txt`.

# License

LightPHE is licensed under the MIT License - see [`LICENSE`](https://github.com/serengil/LightPHE/blob/master/LICENSE) for more details.
