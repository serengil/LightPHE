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

# proof of work
assert cs.decrypt(c) == m
```

# Homomorphic Operations

Once you have the ciphertext, you will be able to perform homomorphic operations on encrypted data without holding private key. For instance, Paillier is homomorphic with respect to the addition. In other words, decryption of the addition of two ciphertexts is equivalent to addition of plaintexts.

### On-Prem Encryption

This Python code snippet demonstrates how to generate a private-public key pair using the Paillier cryptosystem via the LightPHE library. First, an instance of the LightPHE class is created with the Paillier algorithm. Then, the public key is exported and saved to a file named "public.txt" to build the same cryptosystem with only public key in the cloud side later. The code defines two plaintext values, m1 and m2, respectively. These plaintext values are encrypted to generate ciphertexts c1 and c2 using the public key. Finally, the ciphertexts c1 and c2 are prepared to be sent to a cloud system for secure processing or storage.

```python
# generate private-public key pair
cs = LightPHE(algorithm_name = "Paillier")

# export public key to build same cryptosystem with only public key in the cloud
cs.export_keys(target_file = "public.txt", public = True)

# export private key to build same cryptosystem on-prem later
cs.export_keys(target_file = "private.txt", public = False)

# define plaintexts
m1 = 17
m2 = 23

# calculate ciphertexts
c1 = cs.encrypt(m1).value
c2 = cs.encrypt(m2).value

# send c1 and c2 pair to a cloud system
```

### Homomorphic Operations on Cloud

This Python code snippet illustrates how to handle encrypted data on the cloud side using the Paillier cryptosystem with the LightPHE library. Upon receiving the encrypted values c1 and c2, the cloud system initializes the cryptosystem using the exported public key stored in public.txt. To ensure the security of the data, a test is performed to confirm that the cloud system cannot decrypt c1 and c2 without the private key. This is done using the pytest library, which raises a ValueError if decryption is attempted, verifying that decryption is not possible without the private key. Finally, the code demonstrates homomorphic addition by adding the two ciphertexts, resulting in a new ciphertext c3 that represents the encrypted sum of the original plaintext values.

```python
# cloud side receives encrypted c1 and c2

# restore cryptosystem with the exported public key
cs = LightPHE(algorithm_name = "Paillier", key_file = "public.txt")

# convert c1 and c2 to ciphertext objects
c1 = cs.create_ciphertext_obj(c1)
c2 = cs.create_ciphertext_obj(c2)

# confirm that cloud cannot decrypt c1
with pytest.raises(ValueError, match="You must have private key to perform decryption"):
  cs.decrypt(c1)

# confirm that cloud cannot decrypt c2
with pytest.raises(ValueError, match="You must have private key to perform decryption"):
  cs.decrypt(c2)

# homomorphic addition - private key not required
c3 = c1 + c2

# confirm that cloud cannot decrypt c3
with pytest.raises(ValueError, match="You must have private key to perform decryption"):
  cs.decrypt(c3)
```

### On-Prem Decryption

This Python code snippet demonstrates the final step in a secure computation process using homomorphic encryption with the LightPHE library. After receiving the ciphertext c3 from the cloud, which is the result of homomorphic addition of two ciphertexts c1 and c2, the on-premises system (which has the private key) decrypts c3 to verify the result. The decrypted value is then asserted to be equal to the sum of the original plaintext values m1 and m2. This step ensures the correctness of the homomorphic computation performed by the cloud.

```python
# on-prem side receives c3 from cloud

# restore cryptosystem with the exported private key
cs = LightPHE(algorithm_name = "Paillier", key_file = "private.txt")

# proof of work - private key required
assert cs.decrypt(c3) == m1 + m2
```

### Scalar Multiplication

Besides, Paillier is supporting multiplying ciphertexts by a known plain constant. This Python code snippet demonstrates how to perform scalar multiplication on encrypted data using homomorphic encryption with the LightPHE library. The factor k is set to 1.05, representing a 5% increase. On the cloud side, this factor is used to multiply the ciphertext c1, resulting in a new ciphertext c4. When the on-premises system, which holds the private key, receives c4, it decrypts it and verifies that the decrypted value matches the original plaintext m1 scaled by k (i.e., 1.05 * m1). This ensures that the homomorphic scalar multiplication was performed correctly on the encrypted data.

```python
# increasing something 5%
k = 1.05

# scalar multiplication - cloud (private key is not required)
c4 = k * c1

# proof of work on-prem - private key is required
assert cs.decrypt(c4) == k * m1
```

### Ciphertext Regeneration

Similar to the most of additively homomorphic algorithms, Paillier lets you to regenerate ciphertext while you are not breaking its plaintext restoration. You may consider to do this re-generation many times to have stronger ciphertexts.

```python
c1_prime = cs.regenerate_ciphertext(c1)
assert c1_prime.value != c1.value
assert cs.decrypt(c1_prime) == m1
assert cs.decrypt(c1) == m1
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
