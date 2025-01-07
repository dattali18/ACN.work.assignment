"""Encrypted sockets implementation
   Author:
   Date:
"""

import random
import socket
from typing import Tuple
from sympy import isprime
from math import gcd

# Constants
LENGTH_FIELD_SIZE = 2
PORT = 8820
MAC_LENGTH = 16
DIFFIE_HELLMAN_P = 6427  # big prime number
DIFFIE_HELLMAN_G = 3

# Look-up table for encryption
LUT = {i: (i * 0x1B) % 256 for i in range(256)}


def symmetric_encryption(input_data: str, key: int) -> bytes:
    """Encrypt the input data using a symmetric key."""
    key &= 0xFFFF  # Ensure key is 16 bits
    input_bytes = input_data.encode("latin1")

    # 1. XOR with key
    xor_data = bytes((b ^ (key & 0xFF)) % 256 for b in input_bytes)

    # 2. Apply LUT
    lut_data = bytes(LUT[b] for b in xor_data)

    # 3. Shuffle
    shuffle_data = bytes(
        lut_data[(i + 1) % len(lut_data)] for i in range(len(lut_data))
    )

    # 4. XOR with key again
    return bytes((b ^ (key & 0xFF)) % 256 for b in shuffle_data)


def symmetric_decryption(input_data: bytes, key: int) -> str:
    """Decrypt the input data using a symmetric key."""
    key &= 0xFFFF  # Ensure key is 16 bits

    # 1. XOR with key
    xor_data = bytes((b ^ (key & 0xFF)) % 256 for b in input_data)

    # 2. Reverse shuffle
    shuffle_data = bytes(
        xor_data[(i - 1) % len(xor_data)] for i in range(len(xor_data))
    )

    # 3. Reverse LUT
    lut_data = bytes(list(LUT.values()).index(b) for b in shuffle_data)

    # 4. XOR with key again
    decrypted_bytes = bytes((b ^ (key & 0xFF)) % 256 for b in lut_data)

    return decrypted_bytes.decode("latin1")


def diffie_hellman_choose_private_key() -> int:
    """Choose a 16-bit private key for Diffie-Hellman."""
    return random.randint(0, 2**16)


def diffie_hellman_calc_public_key(private_key: int) -> int:
    """Calculate the public key for Diffie-Hellman."""
    return pow(DIFFIE_HELLMAN_G, private_key, DIFFIE_HELLMAN_P)


def diffie_hellman_calc_shared_secret(other_side_public: int, my_private: int) -> int:
    """Calculate the shared secret for Diffie-Hellman."""
    return pow(other_side_public, my_private, DIFFIE_HELLMAN_P)


def calc_hash(message: str) -> int:
    """Create a 16-bit hash from the message."""
    return sum(ord(char) for char in message) % (2**16)


def calc_signature(hash_value: int, RSA_private_key: int, P: int, Q: int) -> int:
    """Calculate the RSA signature."""
    return pow(hash_value, RSA_private_key, P * Q)


def create_msg(data: bytes) -> bytes:
    """Create a valid protocol message with length field."""
    length = len(data)
    return length.to_bytes(4, byteorder="big") + data


def get_msg(my_socket: socket.socket) -> Tuple[bool, bytes]:
    """Extract message from protocol, without the length field."""
    try:
        length_bytes = my_socket.recv(4)
        length = int.from_bytes(length_bytes, byteorder="big")
        message = my_socket.recv(length)
        return True, message
    except:
        return False, b""


def check_RSA_public_key(key: int, totient: int) -> bool:
    """Check if the selected public key satisfies RSA conditions."""
    return isprime(key) and key < totient and totient % key != 0


def get_RSA_private_key(p: int, q: int, public_key: int) -> int:
    """Calculate the RSA private key."""
    totient = (p - 1) * (q - 1)

    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = extended_gcd(public_key, totient)
    if gcd != 1:
        return None
    return x % totient
