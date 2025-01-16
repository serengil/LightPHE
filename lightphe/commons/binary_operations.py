"""
This module is heavily inspired by repo github.com/dimitrijray/ecc-binary-field/blob/master/binop.py
"""


def divide(a: int, b: int, p: int) -> int:
    """
    Returns a_bin * (b_bin)^-1 (mod p)
    Args:
        a (int): nominator
        b (int): denominator
        p (int): modulo
    Returns:
        result (int): (a_bin * (b_bin)^-1 (mod p)) mod p
    """
    result = mod(multi(a, inverse(b, p)), p)
    return result


def multi(a: int, b: int) -> int:
    """
    Multiply two binary numbers in GF(2).
    Args:
        a (int): first number
        b (int): second number
    Returns:
        result (int): carry-less multiplication between a and b
    """
    result = 0
    shift = 0

    while b > 0:
        if b & 1:  # Check if the least significant bit of b is 1
            result ^= a << shift
        shift += 1
        b >>= 1  # Shift b to the right by 1

    return result


def power_mod(num: int, exp: int, modulo: int) -> int:
    """
    Calculate num^exp (mod m) in GF(2).
    Args:
        num (int): base
        exp (int): exponent
        modulo (int): modulo
    Returns:
        result (int): num^exp (mod m)
    """
    result = 1
    base = num % modulo

    while exp > 0:
        if exp & 1:  # Check if the least significant bit of exp is 1
            result = multi(base, result)  # multiply result by base
            result = mod(result, modulo)  # apply modulo

        base = square(base)  # square the base
        exp >>= 1  # right shift exp by 1

    return result


def square(num: int) -> int:
    """
    Square a binary number in GF(2).
    Args:
        num (int): number
    Returns:
        result (int): square of num
    """
    result = 0
    shift = 0

    while num > 0:
        if num & 1:  # Check if the least significant bit of num is 1
            result ^= 1 << (2 * shift)  # Set the appropriate bit in the result

        num >>= 1  # Right shift num by 1
        shift += 1

    return result


def mod(num: int, modulo: int) -> int:
    """
    Perform modulo operation for binary numbers in GF(2).
    Args:
        num (int): number
        modulo (int): modulo
    Returns:
        result (int): num mod modulo
    """
    degP = num.bit_length() - 1
    degR = modulo.bit_length() - 1

    while degP >= degR and degR != 0:
        shift = degP - degR
        num ^= modulo << shift  # Perform XOR to reduce the degree of num
        degP = num.bit_length() - 1  # Update the degree of num

    return num


def div(num: int, modulo: int) -> int:
    """
    Return the quotient of the polynomial division num / modulo in GF(2).
    Args:
        num (int): numerator
        modulo (int): denominator
    Returns:
        result (int): quotient
    """
    deg_p = num.bit_length() - 1
    deg_r = modulo.bit_length() - 1
    q = 0

    while deg_p >= deg_r:
        shift = deg_p - deg_r
        q |= 1 << shift  # Set the corresponding bit in the quotient
        num ^= modulo << shift  # Perform XOR to reduce the degree of num
        deg_p = num.bit_length() - 1  # Update the degree of num

    return q


def inverse(num: int, modulo: int) -> int:
    """
    Calculate the inverse of a binary number modulo a polynomial in GF(2).
    Args:
        num (int): number
        modulo (int): modulo
    Returns:
        result (int): inverse of num mod modulo
    """
    a, b = num, modulo
    p1, p2 = 1, 0

    while b != 1:
        q = div(a, b)
        r = mod(a, b)
        a, b = b, r
        p_a = p1 ^ multi(q, p2)
        p1, p2 = p2, p_a

    return p2
