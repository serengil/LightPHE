"""
This module is heavily inspired by repo github.com/dimitrijray/ecc-binary-field/blob/master/binop.py
"""


def divide(a: int, b: int, p: int) -> int:
    """
    Returns a_bin * (b_bin)^-1 (mod p)
    Args:
        a (int): nominator
        b (int): denominator
        p (str): modulo
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
    b_bin = bin(b)[2:]
    if b_bin[len(b_bin) - 1] == "0":
        c = 0
    elif b_bin[len(b_bin) - 1] == "1":
        c = a
    d = a
    for i in range(1, len(b_bin)):
        d = d << 1
        if b_bin[len(b_bin) - (i + 1)] == "1":
            c = c ^ d

    print(f"{a} x {b} = {c}")
    print(f"{a} x {b} != {a*b}")
    return c


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
    expo = bin(exp)[2:]
    mult = num
    result = 1
    for i in range(len(expo) - 1, -1, -1):
        if expo[i] == "1":
            result = multi(mult, result)
            result = mod(result, modulo)
        mult = square(mult)
    return result


def square(num: int) -> int:
    """
    Square a binary number in GF(2).
    Args:
        num (int): number
    Returns:
        result (int): square of num
    """
    num_bin = bin(num)[2:]
    if num_bin[0] == "0":
        b = 0
    elif num_bin[0] == "1":
        b = 1
    for i in range(1, len(num_bin)):
        b = b << 2
        if num_bin[i] == "1":
            b = b ^ 1
    return b


def mod(num: int, modulo: int) -> int:
    """
    Perform modulo operation for binary numbers in GF(2).
    Args:
        num (int): number
        modulo (int): modulo
    Returns:
        result (int): num mod modulo
    """
    p = num * 1
    r = modulo * 1
    degP = num.bit_length() - 1
    degR = modulo.bit_length() - 1
    if degR != 0:
        while degR <= degP:
            setDeg = degP - degR
            r_1 = r << setDeg
            p = p ^ r_1
            degP = len(bin(p)[2:]) - 1
    else:
        p = 0
    return p


def div(num: int, modulo: int) -> int:
    """
    Return the quotient of the polynomial division num / modulo in GF(2).
    Args:
        num (int): numerator
        modulo (int): denominator
    Returns:
        result (int): quotient
    """
    p = num
    r = modulo
    deg_p = p.bit_length() - 1
    deg_r = modulo.bit_length() - 1
    q = 0
    prev_degree = deg_p - deg_r
    for i in range(prev_degree, -1, -1):
        setDeg = deg_p - deg_r
        q = q << 1
        if i == setDeg:
            r_1 = r << setDeg
            p = p ^ r_1
            deg_p = len(bin(p)[2:]) - 1
            q = q ^ 1
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
    a = num
    b = modulo
    r = b
    p1 = 1
    p2 = 0
    while r != 1:
        r = mod(a, b)
        q = div(a, b)
        a = b
        b = r
        p_a = p1 ^ multi(q, p2)
        p1 = p2
        p2 = p_a
    return p_a
