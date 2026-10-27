# built-in dependencies
from typing import Dict, List, Union

# Secure aggregation of model updates for federated learning. Each client quantizes its
# update to integers and packs many of them into a single plaintext, so it encrypts one
# ciphertext per chunk of values instead of one ciphertext per value. Server sums the
# encrypted updates of clients chunk by chunk, and only the sum is decrypted, e.g. by a
# committee holding shares of the private key with threshold decryption.
#   - quantization: x is scaled by 10^precision and rounded, so it is an integer in [-B, B]
#       where B is max_value scaled the same way
#   - packing: values are shifted by B to be non-negative, and placed into slots of
#       slot_bits bits, i.e. plaintext = sum of (x_i + B) * 2^(slot_bits * i)
#   - headroom: a slot of the sum of c updates is at most c * 2B, so slot_bits is the bit
#       length of max_clients * 2B, and slots never overflow into each other
#   - unpacking: slot of the sum minus c * B is the sum of values of c clients
# Ref: Bonawitz, K. et al. (2017). Practical Secure Aggregation for Privacy-Preserving
#   Machine Learning. ACM CCS 2017.
# Ref: Zhang, C. et al. (2020). BatchCrypt: Efficient Homomorphic Encryption for Cross-Silo
#   Federated Learning. USENIX ATC 2020.


def build_layout(
    length: int, precision: int, max_value: Union[int, float], max_clients: int, modulo: int
) -> Dict[str, int]:
    """
    Build the packing layout of updates
    Args:
        length (int): number of values in an update
        precision (int): number of decimal digits kept after quantization
        max_value (int or float): absolute values of updates must be at most this
        max_clients (int): maximum number of updates to be summed
        modulo (int): plaintext modulo of the cryptosystem
    Returns:
        layout (dict): length, precision, bound, maximum number of clients, slot_bits
            and slots per chunk
    """
    if not isinstance(length, int) or length < 1:
        raise ValueError("Update must have at least one value")
    if not isinstance(max_clients, int) or isinstance(max_clients, bool) or max_clients < 1:
        raise ValueError("Maximum number of clients must be a positive integer")
    if not isinstance(max_value, (int, float)) or isinstance(max_value, bool) or max_value <= 0:
        raise ValueError("Maximum value must be a positive number")
    if not isinstance(precision, int) or precision < 0:
        raise ValueError("Precision must be a non-negative integer")

    bound = round(max_value * 10**precision)
    if bound < 1:
        raise ValueError(f"Maximum value {max_value} is zero after quantization")

    slot_bits = (max_clients * 2 * bound).bit_length()
    # packed plaintexts must be less than the plaintext modulo
    slots = (modulo.bit_length() - 1) // slot_bits
    if slots < 1:
        raise ValueError(
            f"Plaintext space is too small for {slot_bits}-bit slots. Use a larger key size,"
            " a smaller precision, a smaller maximum value or fewer clients."
        )
    return {
        "length": length,
        "precision": precision,
        "bound": bound,
        "max_clients": max_clients,
        "slot_bits": slot_bits,
        "slots": slots,
    }


def pack(update: List[Union[int, float]], layout: Dict[str, int]) -> List[int]:
    """
    Quantize an update and pack its values into plaintexts
    Args:
        update (list of int or float): model update of a client
        layout (dict): output of build_layout
    Returns:
        plaintexts (list of int): one for each chunk of values
    """
    bound = layout["bound"]
    scale = 10 ** layout["precision"]
    slot_bits = layout["slot_bits"]
    slots = layout["slots"]

    shifted = []
    for x in update:
        if not isinstance(x, (int, float)) or isinstance(x, bool):
            raise ValueError("Update must be a list of numbers")
        quantized = round(x * scale)
        if abs(quantized) > bound:
            raise ValueError(f"Value {x} of the update exceeds the maximum value")
        shifted.append(quantized + bound)

    plaintexts = []
    for start in range(0, len(shifted), slots):
        plaintext = 0
        for i, value in enumerate(shifted[start : start + slots]):
            plaintext |= value << (slot_bits * i)
        plaintexts.append(plaintext)
    return plaintexts


def unpack(plaintexts: List[int], layout: Dict[str, int], count: int) -> List[float]:
    """
    Unpack the sum of count updates from decrypted plaintexts
    Args:
        plaintexts (list of int): decrypted chunks of the sum
        layout (dict): output of build_layout
        count (int): number of summed updates
    Returns:
        sum (list of float): sum of updates
    """
    bound = layout["bound"]
    scale = 10 ** layout["precision"]
    slot_bits = layout["slot_bits"]
    slots = layout["slots"]
    mask = (1 << slot_bits) - 1

    values: List[float] = []
    for plaintext in plaintexts:
        for i in range(slots):
            if len(values) == layout["length"]:
                break
            slot = (plaintext >> (slot_bits * i)) & mask
            values.append((slot - count * bound) / scale)
    return values


def chunks_of(layout: Dict[str, int]) -> int:
    """
    Number of chunks of an update
    """
    return -(-layout["length"] // layout["slots"])
