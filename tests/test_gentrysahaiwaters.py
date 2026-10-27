import itertools
import random
import time

import pytest

from lightphe import LightPHE
from lightphe.cryptosystems.GentrySahaiWaters import LOG_Q, LOG_B, ELL, OFFSET, ETA
from lightphe.commons.logger import Logger

logger = Logger(module="tests/test_gentrysahaiwaters.py")

cs = LightPHE(algorithm_name="Gentry-Sahai-Waters", key_size=64)
Q = 2**LOG_Q


@pytest.fixture(scope="module")
def large_cs():
    # ring degree giving about 128-bit security against quantum attacks
    return LightPHE(algorithm_name="Gentry-Sahai-Waters", key_size=2048)


def negacyclic_product(poly1, poly2, q):
    # schoolbook multiplication in Z_q[x] / (x^d + 1)
    d = len(poly1)
    result = [0] * d
    for i in range(d):
        for j in range(d):
            if i + j < d:
                result[i + j] += poly1[i] * poly2[j]
            else:
                result[i + j - d] -= poly1[i] * poly2[j]
    return [x % q for x in result]


def noise_bits(system, ciphertext, bit):
    # phase of the decrypted row minus m q / 2
    s = system.cs.keys["private_key"]["s"]
    c0, c1 = ciphertext.value[ELL - 1]
    phase = (c0[0] + negacyclic_product(list(c1), [x % Q for x in s], Q)[0] - bit * Q // 2) % Q
    phase = phase - Q if phase > Q // 2 else phase
    return abs(phase).bit_length()


def test_truth_tables():
    tic = time.time()
    for a, b in itertools.product([0, 1], repeat=2):
        ca, cb = cs.encrypt(a), cs.encrypt(b)
        assert cs.decrypt(ca) == a
        assert cs.decrypt(ca & cb) == a & b
        assert cs.decrypt(ca * cb) == a * b
        assert cs.decrypt(ca ^ cb) == a ^ b

    # not is exclusive or with 1
    one = cs.encrypt(1)
    assert cs.decrypt(cs.encrypt(0) ^ one) == 1
    assert cs.decrypt(cs.encrypt(1) ^ one) == 0

    # re-randomization
    c = cs.encrypt(1)
    c_prime = cs.regenerate_ciphertext(c)
    assert c_prime.value != c.value
    assert cs.decrypt(c_prime) == 1

    # unsupported homomorphic operations
    with pytest.raises(ValueError):
        _ = c + c_prime

    with pytest.raises(ValueError):
        _ = c * 3

    logger.info(f"✅ Gentry-Sahai-Waters truth tables succeeded in {time.time() - tic:.2f} seconds")


def test_circuits_of_depth_two():
    for a, b, c, d in itertools.product([0, 1], repeat=4):
        ca, cb, cc, cd = [cs.encrypt(x) for x in [a, b, c, d]]
        # product of products
        assert cs.decrypt((ca & cb) & (cc & cd)) == a & b & c & d
        # majority of three
        majority = (ca & cb) ^ (ca & cc) ^ (cb & cc)
        assert cs.decrypt(majority) == int(a + b + c >= 2)
        # exclusive or of products, and product of exclusive ors
        assert cs.decrypt((ca & cb) ^ (cc & cd)) == (a & b) ^ (c & d)
        assert cs.decrypt((ca ^ cb) & (cc ^ cd)) == (a ^ b) & (c ^ d)


def test_long_chain_of_ands():
    # acc = acc & fresh adds a fixed noise each time
    for bits in [[1] * 40, [1] * 20 + [0] + [1] * 19]:
        acc = cs.encrypt(bits[0])
        for bit in bits[1:]:
            acc = acc & cs.encrypt(bit)
        assert cs.decrypt(acc) == min(bits)


def test_ripple_carry_adder():
    # add two encrypted 8-bit integers bit by bit. carry is chained with fresh bits.
    for _ in range(3):
        x, y = random.randrange(256), random.randrange(256)
        x_bits = [cs.encrypt((x >> i) & 1) for i in range(8)]
        y_bits = [cs.encrypt((y >> i) & 1) for i in range(8)]

        carry = cs.encrypt(0)
        result_bits = []
        for a, b in zip(x_bits, y_bits):
            half = a ^ b
            result_bits.append(half ^ carry)
            # carry = a & b ^ carry & (a ^ b)
            carry = (a & b) ^ (carry & half)
        result_bits.append(carry)

        result = sum(cs.decrypt(bit) << i for i, bit in enumerate(result_bits))
        assert result == x + y


def test_keys_are_well_formed():
    # b + a s = e where e is small
    public_key = cs.cs.keys["public_key"]
    d, q, b = public_key["d"], public_key["q"], public_key["b"]
    s = cs.cs.keys["private_key"]["s"]
    a = cs.cs._GentrySahaiWaters__expand(seed=public_key["seed"], d=d)

    assert q == Q
    assert all(abs(x) <= ETA for x in s)
    a_s = negacyclic_product(a, [x % q for x in s], q)
    for x, y in zip(a_s, b):
        error = (x + y) % q
        error = error - q if error > q // 2 else error
        assert abs(error) <= ETA


def test_gadget_decomposition():
    # sum of digits times gadget entries restores the polynomial up to rounding
    assert OFFSET + LOG_B * (ELL - 1) == LOG_Q - 1
    decompose = cs.cs._GentrySahaiWaters__decompose
    gadget = cs.cs._GentrySahaiWaters__gadget
    poly = [random.randrange(Q) for _ in range(64)] + [0, 1, Q - 1, Q // 2, Q // 2 - 1]
    digits = decompose(poly)
    assert len(digits) == ELL
    for i, x in enumerate(poly):
        assert all(-(2 ** (LOG_B - 1)) <= digits[j][i] < 2 ** (LOG_B - 1) for j in range(ELL))
        restored = sum(digits[j][i] * gadget(j) for j in range(ELL))
        error = (x - restored) % Q
        error = error - Q if error > Q // 2 else error
        assert abs(error) <= 2 ** (OFFSET - 1)


def test_invalid_inputs():
    for plaintext in [2, -1, 1.5, [0, 1]]:
        with pytest.raises(ValueError, match="encrypts bits"):
            cs.encrypt(plaintext)

    with pytest.raises(ValueError, match="encrypts bits"):
        _ = cs.encrypt(1) * 1.5

    for key_size in [4, 48, 100]:
        with pytest.raises(ValueError, match="must be a power of 2"):
            LightPHE(algorithm_name="Gentry-Sahai-Waters", key_size=key_size)


def test_exported_keys(tmp_path):
    public_key_file = str(tmp_path / "public.txt")
    cs.export_keys(target_file=public_key_file, public=True)

    public_cs = LightPHE(algorithm_name="Gentry-Sahai-Waters", key_file=public_key_file)
    c = public_cs.encrypt(1) & public_cs.encrypt(1)
    assert cs.decrypt(c) == 1

    with pytest.raises(ValueError, match="private key"):
        public_cs.decrypt(c)


def test_noise_budget_of_large_keys(large_cs):
    # products of products of depth 2 stay below q / 4 = 2^48 for the default degree
    tic = time.time()
    a, b, c, d = [large_cs.encrypt(1) for _ in range(4)]
    assert noise_bits(large_cs, a, 1) <= 16

    ab = a & b
    cd = c & d
    assert noise_bits(large_cs, ab, 1) <= 32

    abcd = ab & cd
    assert large_cs.decrypt(abcd) == 1
    assert noise_bits(large_cs, abcd, 1) <= 46

    # a chain with a fresh ciphertext on the right adds a small noise
    chain = abcd & large_cs.encrypt(0)
    assert large_cs.decrypt(chain) == 0

    logger.info(
        f"✅ Gentry-Sahai-Waters 2048-degree test succeeded in {time.time() - tic:.2f} seconds"
    )
