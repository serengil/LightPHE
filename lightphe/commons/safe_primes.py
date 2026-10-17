# built-in dependencies
import random

# 3rd party dependencies
import sympy

# small primes to sieve safe prime candidates before primality tests
SMALL_PRIMES = list(sympy.primerange(3, 2000))


def find_safe_prime(bits: int, max_tries: int) -> int:
    """
    Find a safe prime p = 2p' + 1 where p' is also prime
    Args:
        bits (int): bit length of p
        max_tries (int): maximum number of tries
    Returns:
        p (int): safe prime
    """
    for _ in range(max_tries * 100):
        p_prime = random.getrandbits(bits - 1) | (1 << (bits - 2)) | 1
        p = 2 * p_prime + 1
        # sieve with small primes first, as primality tests are expensive
        if any(
            (p_prime % s == 0 or p % s == 0) and s < p_prime for s in SMALL_PRIMES
        ):
            continue
        if sympy.isprime(p_prime) and sympy.isprime(p):
            return p
    raise ValueError(f"Failed to find a {bits}-bit safe prime")
