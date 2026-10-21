# LightPHE

<div align="center">

[![PyPI Downloads](https://static.pepy.tech/personalized-badge/lightphe?period=total&units=international_system&left_color=grey&right_color=blue&left_text=downloads)](https://pepy.tech/project/lightphe)
[![Stars](https://img.shields.io/github/stars/serengil/LightPHE?color=yellow&style=flat&label=%E2%AD%90%20stars)](https://github.com/serengil/LightPHE/stargazers)
[![License](http://img.shields.io/:license-MIT-green.svg?style=flat)](https://github.com/serengil/LightPHE/blob/master/LICENSE)
[![DOI](http://img.shields.io/:DOI-10.3390/sym18050832-blue.svg?style=flat)](https://www.mdpi.com/2073-8994/18/5/832)

</div>

<p align="center"><img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/phi.png" width="200" height="240"></p>

LightPHE is a lightweight homomorphic encryption library for python supporting various partially and somewhat homomorphic encryptions schemes such as [`RSA`](https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/), [`ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/), [`Exponential ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/), [`Elliptic Curve ElGamal`](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/) ([`Weierstrass`](https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/), [`Koblitz`](sefiks.com/2016/03/13/the-math-behind-elliptic-curves-over-binary-field/) and [`Edwards`](https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/) forms), [`Paillier`](https://sefiks.com/2023/04/03/a-step-by-step-partially-homomorphic-encryption-example-with-paillier-in-python/), [`Damgard-Jurik`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/), [`Okamoto–Uchiyama`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-okamoto-uchiyama-in-python/), [`Benaloh`](https://sefiks.com/2023/10/06/a-step-by-step-partially-homomorphic-encryption-example-with-benaloh-in-python-from-scratch/), [`Naccache–Stern`](https://sefiks.com/2023/10/26/a-step-by-step-partially-homomorphic-encryption-example-with-naccache-stern-in-python/), [`Goldwasser–Micali`](https://sefiks.com/2023/10/27/a-step-by-step-partially-homomorphic-encryption-example-with-goldwasser-micali-in-python/), [`Sander-Young-Yung`](https://sefiks.com/2026/04/02/a-step-by-step-partially-homomorphic-sander-young-yung-example-in-python/), [`Boneh-Goh-Nissim`](https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/), `Joye-Libert`, `Castagnos-Laguillaumie`, `Ishai-Paskin`, `Damgard-Geisler-Kroigaard`, `Bresson-Catalano-Pointcheval`, `Camenisch-Shoup`, `Elliptic Curve Paillier`, `Regev`, `Brakerski-Vaikuntanathan`, `Freeman-Boneh-Goh-Nissim`, `Gentry-Halevi-Vaikuntanathan`. It also supports [`Catalano-Fiore`](#adding-multiplication-support-to-additive-algorithms) transform to add one multiplication to additively homomorphic ones.

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

In summary, LightPHE is covering following algorithms and these are partially homomorphic and somewhat homomorphic with respect to the operations mentioned in the following table.

| Algorithm | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Bitwise-XOR Homomorphic | Bitwise-AND Homomorphic | Regeneration<br>of Ciphertext | Decision Tree<br>Evaluation | Secure<br>Comparison | Encrypted<br>Argmax |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RSA | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ElGamal | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Exponential ElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Elliptic Curve ElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Elliptic Curve Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Damgard-Jurik | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Benaloh | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Naccache-Stern | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Okamoto-Uchiyama | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Joye-Libert | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Castagnos-Laguillaumie | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Damgard-Geisler-Kroigaard | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Bresson-Catalano-Pointcheval | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Camenisch-Shoup | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Ishai-Paskin | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| Regev | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Goldwasser-Micali | ❌ | ❌ | ❌ | ✅ | ❌ | ✅  | ❌ | ❌ | ❌ |
| Sander-Young-Yung | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Boneh-Goh-Nissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Freeman-Boneh-Goh-Nissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Brakerski-Vaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Gentry-Halevi-Vaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |

1️⃣ Boneh-Goh-Nissim, Freeman-Boneh-Goh-Nissim, Brakerski-Vaikuntanathan and Gentry-Halevi-Vaikuntanathan support one multiplication natively. Most additively homomorphic algorithms can support one multiplication with [Catalano-Fiore transform](#adding-multiplication-support-to-additive-algorithms) as well.

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
  "EllipticCurve-ElGamal",
  "Sander-Young-Yung",
  "Boneh-Goh-Nissim",
  "Joye-Libert",
  "Castagnos-Laguillaumie",
  "Ishai-Paskin",
  "Damgard-Geisler-Kroigaard",
  "Bresson-Catalano-Pointcheval",
  "Camenisch-Shoup",
  "EllipticCurve-Paillier",
  "Regev",
  "Brakerski-Vaikuntanathan",
  "Freeman-Boneh-Goh-Nissim",
  "Gentry-Halevi-Vaikuntanathan",
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

The most of homomorphic algorithms allow you to regenerate ciphertext while you are not breaking its plaintext restoration. You may consider to do this re-generation many times to have stronger ciphertexts.

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

### Decision Trees

LightPHE can evaluate decision trees privately. Suppose a bank has a secret decision tree that decides a customer's credit limit, and a customer has private data. The bank does not want to reveal its tree, and the customer does not want to reveal their data. The customer sends encrypted data, the bank runs its tree on it without seeing it, and only the customer can decrypt the result. The customer learns the credit limit but not the rest of the tree. Two cryptosystems support this: Ishai-Paskin for trees on yes / no answers, and Damgard-Geisler-Kroigaard for trees on numeric features.

#### Decision Trees with Nominal Decisions

Ishai-Paskin evaluates trees whose questions have yes / no answers, in a single round: the customer sends encrypted answers, and the bank sends back the encrypted result.

Let the bank's tree be the following, where questions are numbered 0, 1 and 2 and leaves are credit limits in thousand dollars.

```
                  Q0: has stable income?
                 /no                    \yes
     Q2: owns a house?              Q1: has existing debt?
       /no        \yes               /no           \yes
      0            5               20         Q2: owns a house?
                                                /no       \yes
                                               5          10
```

Each question is written as a tuple of `(question number, what to do if no, what to do if yes)`, and leaves are plain integers. So, the tree above becomes:

```python
credit_limit_tree = (0, (2, 0, 5), (1, 20, (2, 5, 10)))
```

Then, the customer and the bank run the following steps.

```python
# customer builds the cryptosystem and keeps the private key
customer_cs = LightPHE(algorithm_name = "Ishai-Paskin")

# customer shares only the public key with the bank
customer_cs.export_keys(target_file = "public.txt", public = True)

# customer's answers: stable income = yes, existing debt = yes, owns a house = no
answers = [1, 1, 0]

# customer encrypts the answers and sends them to the bank. depth is the maximum
# number of questions on a path of the tree, the bank should share this value
encrypted_answers = customer_cs.encrypt_decision_tree_input(bits = answers, depth = 3)

# bank builds its own cryptosystem with the customer's public key
bank_cs = LightPHE(algorithm_name = "Ishai-Paskin", key_file = "public.txt")

# bank runs its tree on encrypted answers and sends the result back to the customer
encrypted_limit = bank_cs.evaluate_decision_tree(
  tree = credit_limit_tree, encrypted_input = encrypted_answers
)

# customer decrypts the result - only the customer has the private key
assert customer_cs.decrypt(encrypted_limit) == 5
```

The size of the result grows with the depth of the tree, not with the number of its nodes. Still, each extra level makes the computation noticeably slower, so this is practical for shallow trees.

#### Decision Trees with Numeric Decisions

Damgard-Geisler-Kroigaard evaluates decision trees with numeric thresholds instead of yes / no answers, using the secure comparison protocol below at each node. It requires a few rounds of interaction between the customer and the bank, but its cost grows linearly with the number of nodes.

Let the bank's tree be the following, where features are numbered 0 (age), 1 (income in thousand dollars) and 2 (number of open loans), and leaves are credit limits in thousand dollars.

```
                  F1: income <= 40?
                 /yes                \no
       F0: age <= 25?          F2: open loans <= 2?
        /yes      \no            /yes           \no
       0           5            20              10
```

Each decision node is written as a tuple of `(feature index, threshold, what to do if feature <= threshold, what to do otherwise)`, and leaves are plain integers. So, the tree above becomes:

```python
credit_limit_tree = (1, 40, (0, 25, 0, 5), (2, 2, 20, 10))
```

Then, the customer and the bank run the following steps.

```python
# customer: age = 30, income = 75 and open loans = 1
# so, the expected path is income > 40 -> open loans <= 2 -> credit limit of 20
customer_cs = LightPHE(algorithm_name = "Damgard-Geisler-Kroigaard")
encrypted_features = customer_cs.encrypt_decision_tree_input(
  features = [30, 75, 1], bit_length = 8
)

# bank, having the customer's public key only
bank_cs = LightPHE(algorithm_name = "Damgard-Geisler-Kroigaard", key_file = "public.txt")
encrypted_comparisons, bank_state = bank_cs.evaluate_decision_tree_comparisons(
  tree = credit_limit_tree, encrypted_features = encrypted_features
)

# customer answers randomly flipped comparisons, so cannot follow the path in the tree
encrypted_answers = customer_cs.answer_decision_tree_comparisons(encrypted_comparisons)

# bank keeps bank_state secret and finds the reached leaf in encrypted form
encrypted_leaves = bank_cs.evaluate_decision_tree_leaves(
  server_state = bank_state, encrypted_answers = encrypted_answers
)

# customer learns only the credit limit
assert customer_cs.decrypt_decision_tree_output(encrypted_leaves) == 20
```

### Secure Comparison

Damgard-Geisler-Kroigaard lets a client and a server find out whether the client's private value is less than or equal to the server's private value, without revealing the values to each other. For instance, a bidder can check whether their bid beats the reserve price of an auction.

```python
# client encrypts its value bit by bit
client_cs = LightPHE(algorithm_name = "Damgard-Geisler-Kroigaard")
encrypted_bid = client_cs.encrypt_comparison_input(value = 120, bit_length = 16)

# server compares it with its own value having the client's public key only
server_cs = LightPHE(algorithm_name = "Damgard-Geisler-Kroigaard", key_file = "public.txt")
encrypted_result = server_cs.evaluate_comparison(encrypted_input = encrypted_bid, value = 150)

# client learns only whether bid <= reserve price
assert client_cs.decrypt_comparison(encrypted_result) is True
```

### Encrypted Argmax

Damgard-Geisler-Kroigaard can also find the index of the maximum among encrypted values. For instance, a server can compute encrypted class scores of a linear classifier on a client's encrypted features, and then find the predicted class. The client learns only the index, neither the scores nor the intermediate comparisons, and the server learns nothing. The protocol needs a few round trips per value, so the server talks to the client through a callable. Locally, it can be the client's `answer_argmax` directly. Otherwise, wrap your network call with it.

```python
# client encrypts its features
client_cs = LightPHE(algorithm_name = "Damgard-Geisler-Kroigaard")
encrypted_features = [client_cs.encrypt(feature) for feature in [3, 1, 4]]

# server computes class scores with its private weights homomorphically
server_cs = LightPHE(algorithm_name = "Damgard-Geisler-Kroigaard", key_file = "public.txt")
weights = [[1, 2, 0], [0, 1, 3], [2, 0, 1]]
encrypted_scores = []
for class_weights in weights:
  score = encrypted_features[0] * class_weights[0]
  for encrypted_feature, weight in zip(encrypted_features[1:], class_weights[1:]):
    score = score + encrypted_feature * weight
  encrypted_scores.append(score)

# server finds the argmax with the client's help - scores must fit into bit_length bits
encrypted_class = server_cs.evaluate_argmax(
  encrypted_values = encrypted_scores, bit_length = 8, client = client_cs.answer_argmax
)

# client learns only the predicted class
assert client_cs.decrypt(encrypted_class) == 1
```

### Master Key Decryption

Bresson-Catalano-Pointcheval has two ways to decrypt a ciphertext. Each user decrypts with its own private key, while an authority holding the master key decrypts ciphertexts of all users. For instance, a company can let every employee encrypt with their own key, and still recover the data if an employee leaves. Keep in mind that the master key holder can read everything by design.

```python
# authority generates the master key and publishes its public key
authority_cs = LightPHE(algorithm_name = "Bresson-Catalano-Pointcheval")
authority_cs.export_keys(target_file = "public.txt", public = True)

# each user generates its own key pair with the public key of the authority
public_cs = LightPHE(algorithm_name = "Bresson-Catalano-Pointcheval", key_file = "public.txt")
alice_cs = LightPHE(algorithm_name = "Bresson-Catalano-Pointcheval", keys = public_cs.generate_user_keys())
bob_cs = LightPHE(algorithm_name = "Bresson-Catalano-Pointcheval", keys = public_cs.generate_user_keys())

alice_ciphertext = alice_cs.encrypt(100) + alice_cs.encrypt(50)
bob_ciphertext = bob_cs.encrypt(200)

# users decrypt their own ciphertexts only
assert alice_cs.decrypt(alice_ciphertext) == 150
assert alice_cs.decrypt(bob_ciphertext) != 200

# authority decrypts ciphertexts of all users
assert authority_cs.decrypt_with_master_key(alice_ciphertext) == 150
assert authority_cs.decrypt_with_master_key(bob_ciphertext) == 200
```

### Verifiable Encryption

Camenisch-Shoup lets you encrypt a secret for someone else and prove that the ciphertext really contains it, without revealing the secret. For instance, Alice can escrow the private key of her crypto wallet with a trusted third party. A bank, which knows only her public key, verifies that the escrowed ciphertext contains its private key, and the trusted third party can recover it only under the conditions written in the label.

```python
from lightecc import LightECC

# trusted third party builds the cryptosystem and publishes its public key
ttp_cs = LightPHE(algorithm_name = "Camenisch-Shoup")
ttp_cs.export_keys(target_file = "public.txt", public = True)

# alice's wallet key pair on secp256k1
ecc = LightECC(curve_name = "secp256k1")
private_key = 123456789
public_key = ecc.G * private_key

# alice encrypts her private key for the trusted third party with a proof
label = "release only if alice loses access to her wallet"
alice_cs = LightPHE(algorithm_name = "Camenisch-Shoup", key_file = "public.txt")
escrow = alice_cs.encrypt_verifiably(secret = private_key, label = label)

# bank verifies it with public keys only, without learning alice's private key
bank_cs = LightPHE(algorithm_name = "Camenisch-Shoup", key_file = "public.txt")
assert bank_cs.verify_encryption(escrow, public_point = public_key, label = label) is True

# trusted third party recovers the private key under the same label only
assert ttp_cs.decrypt_verifiable_ciphertext(escrow, label = label) == private_key
```

Private keys of other curves can be escrowed by passing `form` and `curve` arguments while building the cryptosystem. Verifiable ciphertexts reject any modification, so homomorphic operations are applied to regular ciphertexts created with `encrypt`.

### Adding Multiplication Support to Additive Algorithms

Additively homomorphic algorithms cannot multiply two ciphertexts. Boosting them with Catalano-Fiore transform adds one multiplication on top of them, without changing the algorithms themselves. This lets you evaluate degree-2 functions on encrypted data, such as dot products of two encrypted vectors, variances or squared distances. It supports Paillier, Damgard-Jurik, Bresson-Catalano-Pointcheval, Camenisch-Shoup, Elliptic Curve Paillier, Joye-Libert, Castagnos-Laguillaumie, Naccache-Stern, Benaloh and Damgard-Geisler-Kroigaard.

```python
# client builds a boosted cryptosystem, and encrypts its private vectors
client_cs = LightPHE(algorithm_name = "Paillier", boost = "Catalano-Fiore")

x = [3, 1, 4]
y = [1, 5, 9]
encrypted_x = [client_cs.encrypt(value) for value in x]
encrypted_y = [client_cs.encrypt(value) for value in y]

# server computes dot product of encrypted vectors - ciphertexts carry the public key only
encrypted_dot = sum(ex * ey for ex, ey in zip(encrypted_x, encrypted_y))

# squared euclidean distance is also a degree-2 function
encrypted_distance = sum((ex - ey) * (ex - ey) for ex, ey in zip(encrypted_x, encrypted_y))

# client decrypts the results
assert client_cs.decrypt(encrypted_dot) == 44
assert client_cs.decrypt(encrypted_distance) == 45
```

Multiplied ciphertexts can be added and multiplied with constants, but not multiplied with ciphertexts again. They keep a pair of ciphertexts for every product, so a dot product of length d grows d times. Only integers are supported.

### Post-Quantum Security

Most algorithms in LightPHE rely on factoring or discrete logarithm problems, which a large enough quantum computer could solve with Shor's algorithm. Regev and Brakerski-Vaikuntanathan rely on learning with errors problems instead, which are believed to be hard for quantum computers too. Their default key sizes give about 128-bit security against quantum attacks.

Regev is additively homomorphic. Its key size is the lattice dimension, and its default is 2048.

```python
cs = LightPHE(algorithm_name = "Regev")

c1 = cs.encrypt(1500)
c2 = cs.encrypt(2500)

assert cs.decrypt(c1 + c2) == 4000
assert cs.decrypt(c1 * 3) == 4500
```

Brakerski-Vaikuntanathan additionally supports one multiplication of ciphertexts like Boneh-Goh-Nissim, but without pairings. Its key size is the degree of its polynomial ring, and its default is 4096.

```python
cs = LightPHE(algorithm_name = "Brakerski-Vaikuntanathan")

c1 = cs.encrypt(15)
c2 = cs.encrypt(25)
c3 = cs.encrypt(100)

# one multiplication, then additions and multiplications with constants
assert cs.decrypt(c1 * c2 + c3) == 475
assert cs.decrypt((c1 * c2) * 2 + c1 * c3) == 2250
```

Every ciphertext of these algorithms carries a small noise, which grows with each homomorphic operation, and decryption silently fails once it grows too much. With default settings, plaintexts must be less than 2^24. Regev has room for thousands of additions or multiplications with constants up to a few thousands, and a product of Brakerski-Vaikuntanathan has room for millions of times more noise. You can increase the plaintext space with `plaintext_limit` argument in exchange of less room for noise. Floats and tensors are not supported.

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

## LightPHE Ecosystem

`LightPHE` is available across multiple programming languages with consistent APIs and native performance for each ecosystem. Choose the port that fits your stack:

| Language | Repository | Ecosystem Focus |
| :--- | :--- | :--- |
| **Python** | [`lightphe`](https://github.com/serengil/lightphe) | AI, Research & Prototyping |
| **Go** | [`lightphe-go`](https://github.com/serengil/lightphe-go) | Cloud-Native & High-Throughput Microservices |
| **Java** | [`lightphe4j`](https://github.com/serengil/lightphe4j) | Enterprise, Banking & Legacy Systems |
| **TypeScript** | [`lightphe-ts`](https://github.com/serengil/lightphe-ts) | Client-Side Privacy & Node.js Backend |

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
@article{lightphe,
  title          = {Sustainable Cryptography: Carbon Asymmetry in Partially Homomorphic Encryption in the Cloud},
  author         = {Ozpinar, Alper and Serengil, Sefik Ilkin},
  journal        = {Symmetry},
  volume         = {18},
  number         = {5},
  pages          = {832},
  url            = {https://www.mdpi.com/2073-8994/18/5/832},
  doi            = {10.3390/sym18050832},
  note           = {Special Issue: Symmetry in Cryptography and Cybersecurity},
  year           = {2026}
}
```

Also, if you use LightPHE in your projects, please add `lightphe` in the `requirements.txt`.

# License

LightPHE is licensed under the MIT License - see [`LICENSE`](https://github.com/serengil/LightPHE/blob/master/LICENSE) for more details.
