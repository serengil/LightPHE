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

### Elliptic Curve Cryptography

ECC is a powerful public-key cryptosystem based on the algebraic structure of elliptic curves over finite fields. The library supports 3 elliptic curve forms (weierstrass, edwards and koblitz) and 100+ standard elliptic curve configurations.

In LightPHE, the [Elliptic Curve ElGamal](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/) scheme is implemented, offering a secure and efficient homomorphic encryption option.

```python
phe = LightPHE(
    algorithm_name="EllipticCurve-ElGamal",
    form="edwards", # or weierstrass, koblitz
)
```

One of the crucial factors that define the security level of an elliptic curve cryptosystem is the order of the curve. The order of a curve is the number of points on the curve, and it directly influences the strength of the encryption. A higher order typically corresponds to a stronger cryptosystem, making it more resistant to cryptographic attacks.

Each curve in LightPHE has a specific order, which is carefully chosen to balance performance and security. By selecting an elliptic curve with a larger order, you increase the security of your cryptographic system, but this may come with a trade-off in computational efficiency. Therefore, choosing the appropriate curve order is a crucial decision based on your application’s security and performance requirements.

See [`curves`](https://github.com/serengil/LightECC#supported-curves) page for a list of all supported forms, curves and their details.

### Vector Embeddings and Tensors

LightPHE supports homomorphic encryption on vector embeddings and tensors. This is useful in privacy-preserving machine learning, secure aggregation, and confidential data processing.

```python
# build a cryptosystem
cs = LightPHE(algorithm_name="Paillier")

# define plain embedding
tensor = [1.005, 2.05, 3.005, 4.005, -5.05, 6, 7.003, 7.002]

# encrypt vector embedding
encrypted_tensors = cs.encrypt(tensor)

# restore embedding
decrypted_tensors = cs.decrypt(encrypted_tensors)

# proof of work
assert all(abs(original - decrypted) < 1e-2 for original, decrypted in zip(tensor, decrypted_tensors))
```

Encrypted embeddings retain their homomorphic properties, enabling secure computations on encrypted data without decryption. For example, two embeddings encrypted using a multiplicatively homomorphic algorithm can be multiplied element-wise.

```python
# build a multiplicatively homomorphic cryptosystem (e.g. RSA)
cs = LightPHE("RSA")

# define plain embeddings
t1 = [1.005, 2.05, -3.5, 3.1, -4]
t2 = [5, 6.2, -7.002, -7.1, 8.02]

# encrypt embeddings
c1, c2 = cs.encrypt(t1), cs.encrypt(t2)

# perform element-wise homomorphic multiplication
c3 = c1 * c2

# proof of work
assert np.allclose(cs.decrypt(c3), [a * b for a, b in zip(t1, t2)], rtol=1e-2)
```

Similarly, two embeddings encrypted with an additively homomorphic algorithm can be added. Additionally, an encrypted embedding can be multiplied by a constant or a plain embedding.

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
c6 = c1 * t3  # Encrypted-plaintext multiplication

# proof of work
assert np.allclose(cs.decrypt(c4), [a + b for a, b in zip(t1, t2)], rtol=1e-2)
assert np.allclose(cs.decrypt(c5), [a * 3 for a in t1], rtol=1e-2)
assert np.allclose(cs.decrypt(c6), [a * b for a, b in zip(t1, t3)], rtol=1e-2)
```

### Vector Similarity Search with PHE

Many machine learning models rely on a two-tower architecture, including facial recognition, reverse image search, recommendation engines, large language models, and more. In this setup, user and item inputs are separately mapped to vector embeddings.

For example, suppose all facial embeddings in your database are encrypted on-prem in advance. When verifying an identity, the attempted facial embedding is generated on an edge device or in the cloud. You can compute the encrypted similarity by performing a dot product between the encrypted vector and the plain vector, ensuring secure comparison without decrypting sensitive data. Only additively homomorphic cryptosystems offer encrypted similarity calculation.

```python
# define a plain vectors for source and target
alpha = [7.1, 5.2, 5.3, 2.4, 3.5, 4.6]  # On-prem vector (user tower)
beta = [5.6, 3.7, 2.8, 4, 0, 5.9]  # Cloud vector (item tower)
expected_similarity = sum(x * y for x, y in zip(alpha, beta))

# build an additively homomorphic cryptosystem (e.g. Paillier) on-prem
cs = LightPHE(algorithm_name = "Paillier", precision = 19)

# export keys
cs.export_keys("secret.txt")
cs.export_keys("public.txt", public=True)

# encrypt source embedding
encrypted_alpha = cs.encrypt(alpha)

# remove cryptosystem and plain alpha not to be leaked in cloud
del cs, alpha

# restore the cryptosystem in cloud with only public key
cloud_cs = LightPHE(algorithm_name = "Paillier", precision = 19, key_file = "public.txt")

# dot product of encrypted and plain embedding pair
encrypted_cosine_similarity = encrypted_alpha @ beta

# computed by the cloud but cloud cannot decrypt it
with pytest.raises(ValueError, match="must have private key"):
    cloud_cs.decrypt(encrypted_cosine_similarity)

# restore the cryptosystem on-prem with secret key
cs = LightPHE(algorithm_name = "Paillier", precision = 19, key_file = "secret.txt")

# decrypt similarity (on prem)
calculated_similarity = cs.decrypt(encrypted_cosine_similarity)[0]

# proof of work
assert abs(calculated_similarity - expected_similarity) < 1e-2
```

## Security Concerns and Considerations

While LightPHE enables encryption using public keys and supports homomorphic operations on encrypted data, it's important to understand a subtle but critical security implication of this approach. Since the it is homomorphic, the cloud (or any third-party processor) can perform computations without knowing the plaintext. However, a malicious actor can still encrypt arbitrary values and craft valid ciphertexts because encryption depends on your public key and it is publicly known. For example, even if a salary is encrypted, an attacker could encrypt 500 USD using your public key and update the encrypted salary with this forged ciphertext — without needing to know the original value.

To mitigate this, we recommend combining LightPHE with digital signature schemes. By keeping a signed audit trail of update operations in a separate log table, you can detect and reject unauthorized changes, and even restore the original data in case of tampering. We suggest checking out [`LightDSA`](https://github.com/serengil/LightDSA), which provides a lightweight cryptographic interface similar to LightPHE and supports popular digital signature algorithms like RSA, DSA, ECDSA, and EdDSA.

# Contributing

All PRs are more than welcome! If you are planning to contribute a large patch, please create an issue first to get any upfront questions or design decisions out of the way first.

You should be able run `make test` and `make lint` commands successfully before committing. Once a PR is created, GitHub test workflow will be run automatically and unit test results will be available in [GitHub actions](https://github.com/serengil/LightPHE/actions/workflows/tests.yml) before approval.

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
