# LightPHE

<div align="center">

[![PyPI Downloads](https://static.pepy.tech/personalized-badge/lightphe?period=total&units=international_system&left_color=grey&right_color=blue&left_text=downloads)](https://pepy.tech/project/lightphe)
[![Stars](https://img.shields.io/github/stars/serengil/LightPHE?color=yellow&style=flat&label=%E2%AD%90%20stars)](https://github.com/serengil/LightPHE/stargazers)
[![License](http://img.shields.io/:license-MIT-green.svg?style=flat)](https://github.com/serengil/LightPHE/blob/master/LICENSE)
[![DOI](http://img.shields.io/:DOI-10.3390/sym18050832-blue.svg?style=flat)](https://www.mdpi.com/2073-8994/18/5/832)

</div>

<p align="center"><img src="https://raw.githubusercontent.com/serengil/LightPHE/master/icons/phi.png" width="200" height="240"></p>

LightPHE is a lightweight homomorphic encryption library for python supporting various partially and somewhat homomorphic encryptions schemes such as [`RSA`](https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/), [`ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/), [`Exponential ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/), [`Elliptic Curve ElGamal`](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/) ([`Weierstrass`](https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/), [`Koblitz`](sefiks.com/2016/03/13/the-math-behind-elliptic-curves-over-binary-field/) and [`Edwards`](https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/) forms), [`Paillier`](https://sefiks.com/2023/04/03/a-step-by-step-partially-homomorphic-encryption-example-with-paillier-in-python/), [`Damgard-Jurik`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/), [`Okamoto–Uchiyama`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-okamoto-uchiyama-in-python/), [`Benaloh`](https://sefiks.com/2023/10/06/a-step-by-step-partially-homomorphic-encryption-example-with-benaloh-in-python-from-scratch/), [`Naccache–Stern`](https://sefiks.com/2023/10/26/a-step-by-step-partially-homomorphic-encryption-example-with-naccache-stern-in-python/), [`Goldwasser–Micali`](https://sefiks.com/2023/10/27/a-step-by-step-partially-homomorphic-encryption-example-with-goldwasser-micali-in-python/), [`Sander-Young-Yung`](https://sefiks.com/2026/04/02/a-step-by-step-partially-homomorphic-sander-young-yung-example-in-python/), [`Boneh-Goh-Nissim`](https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/), `Joye-Libert`, `Castagnos-Laguillaumie`, `Ishai-Paskin`, `Damgard-Geisler-Kroigaard`, `Bresson-Catalano-Pointcheval`, `Camenisch-Shoup`, `Elliptic Curve Paillier`, `Regev`, `Lyubashevsky-Peikert-Regev`, `ML-KEM`, `Brakerski-Vaikuntanathan`, `Freeman-Boneh-Goh-Nissim`, `Gentry-Halevi-Vaikuntanathan`, `Gentry-Sahai-Waters`. It also supports [`Catalano-Fiore`](#adding-multiplication-support-to-additive-algorithms) transform to add one multiplication to additively homomorphic ones.

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

| Algorithm | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Bitwise-XOR Homomorphic | Bitwise-AND Homomorphic | Regeneration<br>of Ciphertext | Decision Tree<br>Evaluation | Secure<br>Comparison | Encrypted<br>Argmax | Threshold<br>Decryption | Zero-Knowledge<br>Proofs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RSA | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ElGamal | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Exponential ElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Elliptic Curve ElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Elliptic Curve Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Damgard-Jurik | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Benaloh | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Naccache-Stern | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Okamoto-Uchiyama | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Joye-Libert | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Castagnos-Laguillaumie | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Damgard-Geisler-Kroigaard | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Bresson-Catalano-Pointcheval | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Camenisch-Shoup | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Ishai-Paskin | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Regev | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Lyubashevsky-Peikert-Regev | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ML-KEM | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Goldwasser-Micali | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Sander-Young-Yung | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Boneh-Goh-Nissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Freeman-Boneh-Goh-Nissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Brakerski-Vaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Gentry-Halevi-Vaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Gentry-Sahai-Waters | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

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
  "Lyubashevsky-Peikert-Regev",
  "ML-KEM",
  "Brakerski-Vaikuntanathan",
  "Freeman-Boneh-Goh-Nissim",
  "Gentry-Halevi-Vaikuntanathan",
  "Gentry-Sahai-Waters",
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

### Sending Ciphertexts over Network

Ciphertexts, proofs and messages of interactive protocols can be serialized into json to be sent to another party. Keys are never serialized, the receiver restores ciphertexts with its own public key. `serialize` handles ciphertexts nested in lists, tuples and dicts, e.g. a ciphertext with its proof, an encrypted update for secure aggregation, or a message sent to the `client` callable of encrypted argmax and nearest neighbor search.

```python
# client encrypts its value and sends it to the server
client_cs = LightPHE(algorithm_name = "Paillier")
data = client_cs.serialize(client_cs.encrypt(17))

# server restores the ciphertext with the client's public key only, and computes on it
server_cs = LightPHE(algorithm_name = "Paillier", keys = {"public_key": client_cs.cs.keys["public_key"]})
c = server_cs.deserialize(data)
response = server_cs.serialize(c + server_cs.encrypt(25))

# client decrypts the response
assert client_cs.decrypt(client_cs.deserialize(response)) == 42

# a single ciphertext can be converted into a dict as well
assert client_cs.decrypt(client_cs.from_dict(c.to_dict())) == 17
```

To run an interactive protocol across machines, wrap the network call with the `client` callable:

```python
def client(message: dict) -> list:
    # e.g. an http request to the client, which answers with
    # client_cs.serialize(client_cs.answer_knn(client_cs.deserialize(body)))
    response = requests.post(CLIENT_URL, data = server_cs.serialize(message))
    return server_cs.deserialize(response.text)

result = server_cs.evaluate_knn(encrypted_query, gallery, k = 2, bit_length = 16, client = client)
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

### Hyperplane and Naive Bayes Classifiers

Together with [decision trees](#decision-trees), Damgard-Geisler-Kroigaard supports the classifiers of Bost et al. over encrypted data: hyperplane classifiers, e.g. logistic regression or linear SVM, and naive Bayes. The client encrypts its features, the server evaluates its private model on them, and finds the predicted class with [encrypted argmax](#encrypted-argmax). The client learns only the predicted class, and the server learns nothing about the features. Scores of classes must fit into about 30 bits, so floats must be quantized to integers.

```python
# client encrypts its features: income and debt in thousands, years of employment, late payments
client_cs = LightPHE(algorithm_name = "Damgard-Geisler-Kroigaard")
encrypted_features = [client_cs.encrypt(x) for x in [85, 20, 6, 0]]

# bank's logistic regression model, quantized by 1000: class 1 approves the loan
server_cs = LightPHE(algorithm_name = "Damgard-Geisler-Kroigaard", keys = {"public_key": client_cs.cs.keys["public_key"]})
weights = [[0, 0, 0, 0], [42, -65, 310, -900]]
biases = [0, -1200]

# absolute values of scores must be less than 2^bit_length
encrypted_class = server_cs.evaluate_hyperplane(
  encrypted_features, weights, bit_length = 16, client = client_cs.answer_argmax, biases = biases
)
assert client_cs.decrypt(encrypted_class) == 1
```

Naive Bayes works with categorical features, which the client encrypts as one-hot vectors. The server quantizes the logarithms of its probabilities, which must be positive, e.g. smoothed with Laplace smoothing.

```python
# continuing with client_cs and server_cs above
# patient encrypts symptoms: fever (no, yes), cough (none, dry, wet), fatigue (no, yes)
encrypted_symptoms = client_cs.encrypt_naive_bayes_input([1, 1, 1], domain_sizes = [2, 3, 2])

# clinic's model: P(diagnosis) and P(symptom | diagnosis) for cold, flu and allergy
priors = [0.36, 0.36, 0.28]
likelihoods = [
  [[0.71, 0.29], [0.12, 0.25, 0.63], [0.71, 0.29]],
  [[0.29, 0.71], [0.12, 0.63, 0.25], [0.29, 0.71]],
  [[0.83, 0.17], [0.57, 0.29, 0.14], [0.67, 0.33]],
]
encrypted_class = server_cs.evaluate_naive_bayes(
  encrypted_symptoms, priors, likelihoods, client = client_cs.answer_argmax
)

# patient learns only the most likely diagnosis: flu
assert client_cs.decrypt(encrypted_class) == 1
```

Scenarios:

- A customer applies for a loan from a mobile app, and the bank runs its credit scoring model on the encrypted income and debts, so the customer learns only whether the loan is approved, and the bank neither reveals its model nor sees the financial details before the customer agrees to share them.
- A patient checks symptoms with an online clinic, whose diagnosis model was trained on years of patient records, so the patient learns the most likely diagnosis without revealing the symptoms, and the clinic does not give away its model.
- An email client asks a spam filtering service whether a message is spam, and the service classifies the encrypted word counts of the message, so it never reads the email.

### Encrypted Nearest Neighbor Search

LightPHE can find the k nearest vectors to an encrypted query, e.g. searching a face embedding in a gallery, without revealing the query. Embeddings must be quantized to integers first, e.g. by scaling and rounding. There are two settings.

If the server owns the gallery in plain, the client encrypts its query with Damgard-Geisler-Kroigaard, and the server finds the nearest vectors with [encrypted argmax](#encrypted-argmax). The server learns neither the query nor the result, and the client learns only the indices or labels of the k nearest vectors, neither the distances nor the other vectors. It needs about 0.6 seconds per vector of the gallery and per nearest vector to find with 1024-bit keys.

```python
# client encrypts its face embedding, quantized to integers
client_cs = LightPHE(algorithm_name = "Damgard-Geisler-Kroigaard")
encrypted_query = client_cs.encrypt_knn_query([12, -7, 33, 5])

# server finds the 2 nearest vectors of its gallery - squared distances must fit into bit_length bits
server_cs = LightPHE(algorithm_name = "Damgard-Geisler-Kroigaard", keys = {"public_key": client_cs.cs.keys["public_key"]})
gallery = [[10, -5, 30, 4], [-40, 22, 1, 9], [13, -8, 35, 6]]
people = [101, 102, 103]
result = server_cs.evaluate_knn(
  encrypted_query, gallery, k = 2, bit_length = 16, client = client_cs.answer_knn, labels = people
)

# client learns only who the nearest people are
assert [client_cs.decrypt(label) for label in result["labels"]] == [103, 101]
```

If the gallery itself is stored in an untrusted cloud, the owner encrypts both the gallery and its queries with the [Catalano-Fiore](#adding-multiplication-support-to-additive-algorithms) boost. The cloud computes encrypted squared distances with the public key only, and the owner decrypts them to find the nearest vectors. The cloud learns nothing.

```python
# owner encrypts its gallery once, uploads it, and then encrypts queries
owner_cs = LightPHE(algorithm_name = "Paillier", boost = "Catalano-Fiore")
gallery = [[10, -5, 30, 4], [-40, 22, 1, 9], [13, -8, 35, 6]]
encrypted_gallery = [[owner_cs.encrypt(x) for x in vector] for vector in gallery]
encrypted_query = [owner_cs.encrypt(x) for x in [12, -7, 33, 5]]

# cloud computes encrypted distances with the public key only
cloud_cs = LightPHE(algorithm_name = "Paillier", keys = {"public_key": owner_cs.cs.keys["public_key"]}, boost = "Catalano-Fiore")
encrypted_distances = cloud_cs.evaluate_knn_distances(encrypted_query, encrypted_gallery)

# owner decrypts them and finds the nearest vectors
assert owner_cs.decrypt_knn(encrypted_distances, k = 2)["indices"] == [2, 0]
```

Scenarios:

- A user unlocks a door by face, and the building's server matches the encrypted face embedding against its gallery of employees, so the server never sees the user's face and the user learns only whether they are recognized, not who else is enrolled.
- A bank checks whether a new customer's encrypted face embedding matches anyone on a sanctions list held by a screening provider, so the provider does not learn the customer and the bank does not get the list.
- A company keeps the face embeddings of its employees in a public cloud, and searches them with encrypted queries, so a breach of the cloud reveals neither the gallery nor the queries.
- A retailer recommends products by finding the nearest items to a user's encrypted preference vector, so the server does not learn the user's taste.

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

### Threshold Decryption

ElGamal, Exponential ElGamal, Elliptic Curve ElGamal, Paillier and Damgard-Jurik support threshold decryption. ElGamal and Exponential ElGamal keys must be generated with `prime_order = True` for this. A dealer splits the private key into shares, and any `threshold` of `parties` shareholders decrypt a ciphertext together, whereas fewer shareholders learn nothing. For instance, a board of 5 directors can let any 3 of them decrypt the company's encrypted data, so neither a single director can read it alone nor losing 2 of them blocks access.

```python
# dealer splits the private key into 5 shares, any 3 of them can decrypt
dealer_cs = LightPHE(algorithm_name = "Paillier")
share_keys = dealer_cs.generate_threshold_keys(threshold = 3, parties = 5)

# dealer forgets the private key, and publishes the public key with threshold parameters
dealer_cs.export_keys(target_file = "public.txt", public = True)

# each share key is sent to its own shareholder secretly
shareholders = [LightPHE(algorithm_name = "Paillier", keys = keys) for keys in share_keys]

# anyone encrypts and computes homomorphically with the public key
public_cs = LightPHE(algorithm_name = "Paillier", key_file = "public.txt")
c = public_cs.encrypt(100) + public_cs.encrypt(50)

# any 3 shareholders decrypt partially, a single partial decryption reveals nothing
partials = [shareholders[i].partial_decrypt(c) for i in [0, 2, 4]]

# anyone having the public key combines partial decryptions
assert public_cs.combine_partial_decryptions(c, partials) == 150
```

The dealer knows the private key while splitting it, so it must be trusted. By default, partial decryptions are not proven, so a cheating shareholder can cause a wrong plaintext silently. [Proof of partial decryption](#proof-of-partial-decryption) prevents this.

### Secure Aggregation for Federated Learning

In federated learning, clients train a model on their private data and send only model updates to a server, but updates can still leak the data. LightPHE lets clients encrypt their updates, the server sum them without decrypting, and a committee holding shares of the private key decrypt only the sum with [threshold decryption](#threshold-decryption). Updates are quantized with the precision of the cryptosystem, and many values are packed into a single ciphertext, so a client encrypts one ciphertext per chunk instead of one per value. With 1024-bit keys, 40 values fit into a ciphertext, and encrypting an update of 1000 values takes about 0.5 seconds instead of 13 seconds without packing. Paillier and Damgard-Jurik support this.

```python
# dealer splits the key among a committee of 5, any 3 of them can decrypt
dealer_cs = LightPHE(algorithm_name = "Paillier", safe_primes = True)
share_keys = dealer_cs.generate_threshold_keys(threshold = 3, parties = 5)
committee = [LightPHE(algorithm_name = "Paillier", keys = keys) for keys in share_keys]
public_key = {"public_key": dealer_cs.cs.keys["public_key"]}

# each client encrypts its update with the public key - values must be in [-max_value, max_value]
client_cs = LightPHE(algorithm_name = "Paillier", keys = public_key)
updates = [[0.12, -0.53, 0.98], [0.33, 0.21, -0.47], [-0.25, 0.08, 0.61]]
encrypted_updates = [client_cs.encrypt_update(update, max_value = 1, max_clients = 100) for update in updates]

# server sums encrypted updates without decrypting them
server_cs = LightPHE(algorithm_name = "Paillier", keys = public_key)
encrypted_sum = server_cs.aggregate_updates(encrypted_updates)

# any 3 members decrypt the sum only, and prove their partial decryptions
partials = [member.partial_decrypt_aggregate(encrypted_sum, prove = True) for member in committee[:3]]
result = server_cs.combine_aggregate(encrypted_sum, partials, verify = True)

assert [round(x, 2) for x in result["mean"]] == [0.07, -0.08, 0.37]
```

`max_clients` reserves room in each slot, so that the sum of that many updates never overflows into the next value, and the server refuses to sum more. Clients must use the same key, length, precision, `max_value` and `max_clients`. Updates of dropped clients are simply not summed, and the sum can still be decrypted if up to 2 committee members drop out.

Scenarios:

- Hospitals train a model to detect tumors on their own scans, and a central server averages their encrypted model updates, so neither the server nor the other hospitals see any hospital's update, which could leak information about its patients.
- A keyboard app improves next-word prediction from millions of phones, and a committee of independent organizations decrypts only the average update of each round, so no single party, including the app maker, can inspect the update of a particular phone.
- Banks build a shared fraud detection model, and verified partial decryptions stop a dishonest committee member from slipping a manipulated average into the shared model.

### Zero-Knowledge Proofs

LightPHE lets you prove facts about ciphertexts and decryptions without revealing the plaintexts or the private key, and anyone having the public key can verify them. For instance, a voter proves that a ballot is 0 or 1, an employee proves that an encrypted salary is in a sensible range, and an authority proves that the announced tally is really what the encrypted tally contains.

| Algorithm | Proof of<br>Decryption | Proof of<br>Partial Decryption | Proof of<br>Knowledge | Proof of<br>Allowed Values | Proof of<br>Range | E-Voting | Verifiable<br>Encryption |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ElGamal | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Exponential ElGamal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Elliptic Curve ElGamal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Paillier | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Damgard-Jurik | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Camenisch-Shoup | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

ElGamal and Exponential ElGamal keys must be generated with `prime_order = True` for proofs. Paillier and Damgard-Jurik keys must be generated with `safe_primes = True` for proof of partial decryption.

#### Proof of Decryption

The private key owner can prove that a ciphertext decrypts to a plaintext, and anyone can check it with the public key only. ElGamal family uses a Chaum-Pedersen zero-knowledge proof, so the private key is never revealed. Paillier and Damgard-Jurik reveal the randomness of the ciphertext instead, which proves the plaintext and reveals nothing about the private key or other ciphertexts.

```python
# private key owner builds the cryptosystem and publishes its public key
cs = LightPHE(algorithm_name = "Exponential-ElGamal", prime_order = True)
cs.export_keys(target_file = "public.txt", public = True)
public_cs = LightPHE(algorithm_name = "Exponential-ElGamal", key_file = "public.txt")

c = public_cs.encrypt(17) + public_cs.encrypt(25)

# private key owner decrypts with a proof
plaintext, proof = cs.decrypt_with_proof(c)

# anyone verifies it with public key only
assert public_cs.verify_decryption(c, plaintext, proof) is True
assert public_cs.verify_decryption(c, plaintext + 1, proof) is False
```

Scenarios:

- An election authority announces that 5,000 of 8,000 encrypted ballots are yes, and publishes a proof, so every voter can check that the announced result is really what the encrypted tally contains without trusting the authority.
- A cloud service computes the average salary over encrypted payroll data of a client company and decrypts it with a proof, so an external auditor can confirm that the reported average was not altered on its way to the board.
- A bank publishes the decrypted total of a day's encrypted transactions together with a proof, so a regulator can verify the total without being given the bank's private key or the individual transactions.

#### Proof of Partial Decryption

In [threshold decryption](#threshold-decryption), a cheating shareholder can send a wrong partial decryption and cause a wrong plaintext silently. A cheating shareholder can even shift the result by any amount it chooses, e.g. add 50 votes to a party, because lagrange coefficients of other shareholders are public. Shareholders can opt in to prove that their partial decryptions are computed with their own shares, and the combiner can opt in to verify them. Then, invalid or unproven partial decryptions are discarded. Paillier and Damgard-Jurik keys must be generated with `safe_primes = True` for this, e.g. `LightPHE(algorithm_name = "Paillier", safe_primes = True)`.

```python
# dealer splits the private key into 3 shares, any 2 of them can decrypt
dealer_cs = LightPHE(algorithm_name = "Exponential-ElGamal", prime_order = True)
share_keys = dealer_cs.generate_threshold_keys(threshold = 2, parties = 3)
shareholders = [LightPHE(algorithm_name = "Exponential-ElGamal", keys = keys) for keys in share_keys]

c = dealer_cs.encrypt(42)

# shareholders opt in to prove their partial decryptions
partials = [shareholder.partial_decrypt(c, prove = True) for shareholder in shareholders]

# anyone verifies a partial decryption with public key only, e.g. to find a cheating shareholder
assert dealer_cs.verify_partial_decryption(c, partials[0]) is True

# combiner opts in to verify partial decryptions while combining them
assert dealer_cs.combine_partial_decryptions(c, partials, verify = True) == 42
```

Scenarios:

- Three trustees nominated by competing parties decrypt an election tally together, so a trustee who tries to add 50 votes to its own party by tampering with its partial decryption is detected and outvoted by the honest two.
- Five hospitals hold shares of a key protecting encrypted patient statistics, and any three of them decrypt the yearly average together, so a single hospital cannot quietly bias the published average in its favor.
- Servers of a federated learning committee decrypt the sum of encrypted model updates from thousands of phones, so a compromised server cannot slip a poisoned update into the global model without being caught.
- Two of three auditors are required to open the total of a company's encrypted transactions, so an auditor bribed to hide a loss cannot misreport the total.

#### Proof of Knowledge

Anyone having the public key can encrypt a value and prove knowledge of it, without revealing it. Otherwise, someone could copy another one's ciphertext, re-randomize it or modify it homomorphically, and submit it as their own without knowing the plaintext. The proof is bound to the ciphertext and a context such as the id of the encryptor.

```python
cs = LightPHE(algorithm_name = "Paillier")

# alice submits her sealed bid with a proof of knowledge
alice_bid, alice_proof = cs.encrypt_with_proof_of_knowledge(950, context = "alice")
assert cs.verify_knowledge(alice_bid, alice_proof, context = "alice") is True

# mallory outbids alice by adding 1 to her encrypted bid without knowing it, but cannot prove it
mallory_bid = alice_bid + cs.encrypt(1)
assert cs.verify_knowledge(mallory_bid, alice_proof, context = "mallory") is False
```

Scenarios:

- In a sealed-bid auction, Mallory sees Alice's encrypted bid and submits it plus 1 to win by the smallest margin without knowing the amount, but she cannot prove knowledge of that bid, so her submission is rejected.
- On a crowdfunding platform, a backer cannot copy a large encrypted pledge of another backer and scale it to look generous, because each pledge must come with a proof that its owner knows the amount.
- In an encrypted employee survey, a participant cannot re-randomize a colleague's encrypted answer and submit it as their own to double its weight, because a re-randomized copy cannot be proven.

#### Proof of Allowed Values

Anyone having the public key can encrypt a value and prove that it is one of the allowed values, without revealing which one. The proof is bound to a context such as the id of the encryptor, so a copied ciphertext with its proof is rejected for another context.

```python
cs = LightPHE(algorithm_name = "Paillier")

# a customer rates a product from 1 to 5 stars, and proves it without revealing the rating
rating, proof = cs.encrypt_with_proof(4, values = [1, 2, 3, 4, 5], context = "customer-42")

# anyone verifies it with public key only
assert cs.verify_ciphertext(rating, proof, values = [1, 2, 3, 4, 5], context = "customer-42") is True
assert cs.verify_ciphertext(rating, proof, values = [1, 2, 3, 4, 5], context = "customer-43") is False
```

Scenarios:

- An online shop collects encrypted product ratings, and each customer proves that the rating is between 1 and 5 stars, so nobody can submit a rating of 1,000 to push the average up while individual ratings stay private.
- A company runs an anonymous satisfaction survey with answers from 1 (poor) to 4 (excellent), and each employee proves that the encrypted answer is one of them, so the average satisfaction is computed homomorphically and a malformed answer cannot corrupt it.
- In [e-voting](#e-voting), each voter proves that the ballot is 0 or 1, so nobody can cast a vote of 100 in the homomorphic tally without revealing how they voted.

#### Proof of Range

Anyone having the public key can encrypt a value and prove that it is in `[low, high]`, without revealing it. Proof size grows with the bit length of `high - low`.

```python
cs = LightPHE(algorithm_name = "Paillier")

# an employee proves that the encrypted salary is in [0, 500000], so cannot skew the average
salary, proof = cs.encrypt_with_range_proof(85000, low = 0, high = 500000, context = "alice")

# anyone verifies it with public key only
assert cs.verify_range(salary, proof, low = 0, high = 500000, context = "alice") is True
assert cs.verify_range(salary, proof, low = 0, high = 50000, context = "alice") is False
```

Scenarios:

- In an industry salary survey, each employee encrypts the salary with a proof that it is between 0 and 500,000, so a single participant cannot submit a negative or a billion-dollar salary to skew the published average.
- A website requires visitors to be adults, and a visitor proves that the encrypted age is between 18 and 120 without revealing the exact age or birth date.
- In a participatory budget, each citizen allocates up to 1,000 to public projects in encrypted form, so allocations are proven to be within the cap while individual preferences stay private.
- A lender accepts an encrypted credit score with a proof that it is between 650 and 850, so the applicant shows eligibility without revealing the exact score.

#### E-Voting

[Proof of allowed values](#proof-of-allowed-values) makes e-voting possible. Each voter proves that a ballot is 0 or 1, so cannot cast a vote of 100 in the homomorphic tally. The proof is bound to the id of the voter, so a copied ballot is rejected. Then, the authority decrypts the tally with a [proof of decryption](#proof-of-decryption).

```python
# authority builds the cryptosystem and publishes its public key
authority_cs = LightPHE(algorithm_name = "Exponential-ElGamal", prime_order = True)
authority_cs.export_keys(target_file = "public.txt", public = True)
public_cs = LightPHE(algorithm_name = "Exponential-ElGamal", key_file = "public.txt")

# each voter encrypts a vote of 0 or 1 with a proof, having the public key only
alice_ballot, alice_proof = public_cs.encrypt_with_proof(1, values = [0, 1], context = "alice")
bob_ballot, bob_proof = public_cs.encrypt_with_proof(0, values = [0, 1], context = "bob")

# anyone verifies ballots without decrypting them
assert public_cs.verify_ciphertext(alice_ballot, alice_proof, values = [0, 1], context = "alice") is True
assert public_cs.verify_ciphertext(bob_ballot, bob_proof, values = [0, 1], context = "bob") is True

# mallory's copy of alice's ballot is rejected
assert public_cs.verify_ciphertext(alice_ballot, alice_proof, values = [0, 1], context = "mallory") is False

# valid ballots are tallied homomorphically, and the authority decrypts the tally with a proof
tally = alice_ballot + bob_ballot
result, proof = authority_cs.decrypt_with_proof(tally)
assert public_cs.verify_decryption(tally, result, proof) is True
assert result == 1
```

For an election of parties, a vote for party `k` can be encrypted as `base^k`, so the tally keeps the votes of each party in its own digit in that base. The proof guarantees that a voter votes once for exactly one party. `base` must be greater than the votes a party can get, e.g. 100 allows up to 99 votes per party, and `base^parties` must be less than the modulus. Paillier fits here, as the tally is a large number.

```python
# authority builds the cryptosystem and publishes its public key
authority_cs = LightPHE(algorithm_name = "Paillier")
authority_cs.export_keys(target_file = "public.txt", public = True)
public_cs = LightPHE(algorithm_name = "Paillier", key_file = "public.txt")

# a vote for party k is encrypted as 100^k, i.e. 1 for red, 100 for green and 10000 for blue
parties = ["red", "green", "blue"]
values = [100 ** k for k in range(len(parties))]

# each voter encrypts a vote for one party with a proof
alice_ballot, alice_proof = public_cs.encrypt_with_proof(values[0], values = values, context = "alice")
bob_ballot, bob_proof = public_cs.encrypt_with_proof(values[2], values = values, context = "bob")
carol_ballot, carol_proof = public_cs.encrypt_with_proof(values[0], values = values, context = "carol")

# anyone verifies ballots without decrypting them
assert public_cs.verify_ciphertext(alice_ballot, alice_proof, values = values, context = "alice") is True
assert public_cs.verify_ciphertext(bob_ballot, bob_proof, values = values, context = "bob") is True
assert public_cs.verify_ciphertext(carol_ballot, carol_proof, values = values, context = "carol") is True

# valid ballots are tallied homomorphically, and the authority decrypts the tally with a proof
tally = alice_ballot + bob_ballot + carol_ballot
result, proof = authority_cs.decrypt_with_proof(tally)
assert public_cs.verify_decryption(tally, result, proof) is True

# tally is 2 x 1 + 0 x 100 + 1 x 10000 = 10002, read 2 digits at a time from right: 1 | 00 | 02
votes = {party: (result // 100 ** k) % 100 for k, party in enumerate(parties)}
assert votes == {"red": 2, "green": 0, "blue": 1}
```

Alternatively, for an election of many parties, each voter casts a one-hot ballot, i.e. one ciphertext per party where only the chosen party is 1, with a proof that exactly one party is chosen. Summing ballots slot by slot counts the votes of each party separately, so the number of parties is not limited.

```python
# authority builds the cryptosystem and publishes its public key
authority_cs = LightPHE(algorithm_name = "Exponential-ElGamal", prime_order = True)
authority_cs.export_keys(target_file = "public.txt", public = True)
public_cs = LightPHE(algorithm_name = "Exponential-ElGamal", key_file = "public.txt")

parties = ["red", "green", "blue", "yellow"]

# each voter encrypts a vote for one party as a one-hot ballot with a proof
alice_ballot, alice_proof = public_cs.encrypt_one_hot(parties.index("red"), options = len(parties), context = "alice")
bob_ballot, bob_proof = public_cs.encrypt_one_hot(parties.index("blue"), options = len(parties), context = "bob")
carol_ballot, carol_proof = public_cs.encrypt_one_hot(parties.index("red"), options = len(parties), context = "carol")

# anyone verifies ballots without decrypting them
assert public_cs.verify_one_hot(alice_ballot, alice_proof, context = "alice") is True
assert public_cs.verify_one_hot(bob_ballot, bob_proof, context = "bob") is True
assert public_cs.verify_one_hot(carol_ballot, carol_proof, context = "carol") is True

# valid ballots are summed slot by slot, so each party's votes are counted in its own ciphertext
tally = [a + b + c for a, b, c in zip(alice_ballot, bob_ballot, carol_ballot)]

# authority decrypts the count of each party with a proof
votes = {}
for party, count in zip(parties, tally):
    result, proof = authority_cs.decrypt_with_proof(count)
    assert public_cs.verify_decryption(count, result, proof) is True
    votes[party] = result

assert votes == {"red": 2, "green": 0, "blue": 1, "yellow": 0}
```

Scenarios:

- A city runs a referendum on a new park, and every resident casts an encrypted yes or no ballot with a proof, so the city announces the result with a proof of decryption while nobody, including the city, learns how an individual voted.
- A national election of a few parties encrypts a vote for party k as `base^k`, so a single homomorphic sum and a single decryption reveal the votes of every party at once.
- A national election of dozens of parties uses one-hot ballots of `encrypt_one_hot` and `verify_one_hot`, so each party's votes are counted in its own ciphertext and the number of parties is not limited.
- Shareholders of a company vote on the board's proposals, and three independent trustees decrypt the tally with [threshold decryption](#threshold-decryption) and [proof of partial decryption](#proof-of-partial-decryption), so no single trustee can read or alter the result.

#### Verifiable Encryption

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

Scenarios:

- Alice escrows the private key of her crypto wallet with a trusted third party, and her bank verifies that the escrow really contains the key before granting her a loan, without ever seeing the key.
- A company escrows the encryption keys of its employees with a recovery service, so an auditor can verify that every key is recoverable if an employee leaves, while neither the auditor nor the service can use the keys under normal conditions.
- A crypto exchange verifies that a customer's key is escrowed under conditions agreed with a regulator, e.g. release only with a court order, without learning the key itself.

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

Most algorithms in LightPHE rely on factoring or discrete logarithm problems, which a large enough quantum computer could solve with Shor's algorithm. Regev, Lyubashevsky-Peikert-Regev, ML-KEM, Brakerski-Vaikuntanathan and Gentry-Sahai-Waters rely on learning with errors problems instead, which are believed to be hard for quantum computers too. Their default key sizes give about 128-bit security against quantum attacks.

Regev is additively homomorphic. Its key size is the lattice dimension, and its default is 2048.

```python
cs = LightPHE(algorithm_name = "Regev")

c1 = cs.encrypt(1500)
c2 = cs.encrypt(2500)

assert cs.decrypt(c1 + c2) == 4000
assert cs.decrypt(c1 * 3) == 4500
```

Lyubashevsky-Peikert-Regev is Regev over a polynomial ring, so its security relies on the ring learning with errors problem like Brakerski-Vaikuntanathan. Its random matrix is replaced by a single polynomial, so it generates keys about 10 times faster and encrypts about 2 times faster than Regev with the same key and ciphertext sizes. Its key size is the degree of its polynomial ring, and its default is 2048.

```python
cs = LightPHE(algorithm_name = "Lyubashevsky-Peikert-Regev")

c1 = cs.encrypt(1500)
c2 = cs.encrypt(2500)

assert cs.decrypt(c1 + c2) == 4000
assert cs.decrypt(c1 * 3) == 4500
```

ML-KEM uses the parameter sets standardized by NIST in FIPS 203: ML-KEM-512, ML-KEM-768 and ML-KEM-1024. It is homomorphic with respect to the exclusive or of 256-bit messages like Goldwasser-Micali. Its key size is the parameter set, and its default is 768. Notice that this is the CPA secure public key encryption K-PKE inside ML-KEM, without ciphertext compression and without the transform that makes ML-KEM CCA secure, because a CCA secure scheme cannot be homomorphic. So, it is not a FIPS 203 compliant ML-KEM implementation, and its keys and ciphertexts are not interoperable with other libraries. Its modulus is small, so only a few ciphertexts can be combined: exclusive or of 6 ciphertexts fails with a probability of about 2^-50 for ML-KEM-768.

```python
cs = LightPHE(algorithm_name = "ML-KEM")

m1 = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
m2 = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321

c1 = cs.encrypt(m1)
c2 = cs.encrypt(m2)

assert cs.decrypt(c1 ^ c2) == m1 ^ m2
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

Gentry-Sahai-Waters encrypts bits, and supports both exclusive or and and, so boolean circuits can be evaluated on encrypted bits with more than one multiplication. Exclusive or is almost free. Products of products work up to a multiplicative depth of 2, e.g. `(a & b) & (c & d)`, whereas chains like `acc = acc & fresh`, e.g. carries of a ripple carry adder, can be very long because each step adds a small fixed noise. Its key size is the degree of its polynomial ring, and its default is 2048. Encrypting a bit takes about 0.5 seconds, an and takes about 1.2 seconds, and a ciphertext is about 256 KB.

```python
cs = LightPHE(algorithm_name = "Gentry-Sahai-Waters")

a, b, c, d = cs.encrypt(1), cs.encrypt(1), cs.encrypt(0), cs.encrypt(1)

# majority of three bits, and a product of products
assert cs.decrypt((a & b) ^ (a & c) ^ (b & c)) == 1
assert cs.decrypt((a & b) & (c & d)) == 0
```

Every ciphertext of these algorithms carries a small noise, which grows with each homomorphic operation, and decryption silently fails once it grows too much. With default settings, plaintexts must be less than 2^24. Regev and Lyubashevsky-Peikert-Regev have room for thousands of additions or multiplications with constants up to a few thousands, and a product of Brakerski-Vaikuntanathan has room for millions of times more noise. You can increase the plaintext space with `plaintext_limit` argument in exchange of less room for noise. Floats and tensors are not supported.

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
