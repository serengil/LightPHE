"""
This module is heavily inspired by repo github.com/dimitrijray/ecc-binary-field/blob/master/binop.py
"""


def xor(a_bin: str, b_bin: str) -> str:
    """
    Perform bitwise-XOR-ing between A and B
    Args:
        a (str): binary string
        b (str): binary string
    Returns:
        result (str): bitwise-XOR-ing between A and B
    """
    a = int(a_bin, 2)
    b = int(b_bin, 2)
    result = a ^ b
    return bin(result)[2:]


def divide(a_bin: str, b_bin: str, p: str) -> str:
    """
    Returns a_bin * (b_bin)^-1 (mod p)
    Args:
        a_bin (str): binary string
        b_bin (str): binary string
        p (str): modulo as binary string
    Returns:
        result (str): a_bin * (b_bin)^-1 (mod p)
    """
    result = mod(multi(a_bin, inverse(b_bin, p)), p)
    return result


def multi(a_bin: str, b_bin: str) -> str:
    """
    Multiply two binary strings
    Args:
        a_bin (str): binary string
        b_bin (str): binary string
    Returns:
        result (str): multiplication between A and B
    """
    a = int(a_bin, 2)
    if b_bin[len(b_bin) - 1] == "0":
        c = 0
    elif b_bin[len(b_bin) - 1] == "1":
        c = a
    d = a
    for i in range(1, len(b_bin)):
        d = d << 1
        if b_bin[len(b_bin) - (i + 1)] == "1":
            c = c ^ d
    return bin(c)[2:]


def power_mod(num: str, exp: int, modulo: str) -> str:
    """
    Calculate num^exp (mod m)
    Args:
        num (str): binary string
        exp (int): exponent as integer
        modulo (str): binary string
    Returns:
        result (str): num^exp (mod m)
    """
    expo = bin(exp)[2:]
    mult = num
    result = "1"
    for i in range(len(expo) - 1, -1, -1):
        if expo[i] == "1":
            result = multi(mult, result)
            result = mod(result, modulo)
        mult = square(mult)
    return result


def square(num: str) -> str:
    """
    Returns squared value of given number
    Args:
        num (str): binary string
    Returns:
        result (str): squared value of given number
    """
    if num[0] == "0":
        b = 0
    elif num[0] == "1":
        b = 1
    for i in range(1, len(num)):
        b = b << 2
        if num[i] == "1":
            b = b ^ 1
    return bin(b)[2:]


def mod(num: str, modulo: str) -> str:
    """
    Returns the remainder of the polynomial division num/numR
    Args:
        num (str): binary string
        modulo (str): binary string
    Returns:
        result (str): remainder of the polynomial division
    """
    p = int(num, 2)
    r = int(modulo, 2)
    degP = len(num) - 1
    degR = len(modulo) - 1
    if degR != 0:
        while degR <= degP:
            setDeg = degP - degR
            r_1 = r << setDeg
            p = p ^ r_1
            degP = len(bin(p)[2:]) - 1
    else:
        p = 0
    return bin(p)[2:]


def div(num: str, modulo: str) -> str:
    """
    Returns the quotient of the polynomial division num/numR
    Args:
        num (str): binary string
        modulo (str): binary string
    Returns:
        result (str): quotient of the polynomial division
    """
    p = int(num, 2)
    r = int(modulo, 2)
    deg_p = len(num) - 1
    deg_r = len(modulo) - 1
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
    return bin(q)[2:]


def inverse(num: str, modulo: str) -> str:
    """
    Returns inverse of a given binary number for a modulo
    Args:
        num (str): binary string
        modulo (str): binary string
    Returns:
        result (str): inverse of a given binary number for a modulo
    """
    a = num
    b = modulo
    r = b
    p1 = "1"
    p2 = "0"
    while r != "1":
        r = mod(a, b)
        q = div(a, b)
        a = b
        b = r
        p_a = xor(p1, multi(q, p2))
        p1 = p2
        p2 = p_a
    return p_a
