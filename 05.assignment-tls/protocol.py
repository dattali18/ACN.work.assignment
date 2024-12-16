"""
Encrypted sockets implementation
   Author:Daniel Attali
   Date: 16/12/2024
"""

import random

LENGTH_FIELD_SIZE = 2
PORT = 8820

DIFFIE_HELLMAN_P = 46049
DIFFIE_HELLMAN_G = 42571


def symmetric_encryption(input_data: bytes, key: int) -> bytes:
    result = bytearray()
    effective_key = key & 0xFF if len(input_data) % 2 == 1 else key
    for i, byte in enumerate(input_data):
        xor_key = (
            key >> 8 if effective_key == key and i % 2 == 0 else effective_key & 0xFF
        )
        result.append(byte ^ xor_key)
    return bytes(result)


def diffie_hellman_choose_private_key():
    return random.randint(1, 2**16 - 1)  # 16-bit range


def diffie_hellman_calc_public_key(private_key: int) -> int:
    return pow(DIFFIE_HELLMAN_G, private_key, DIFFIE_HELLMAN_P)


def diffie_hellman_calc_shared_secret(other_side_public: int, my_private: int) -> int:
    return pow(other_side_public, my_private, DIFFIE_HELLMAN_P)


def calc_hash(message: bytes) -> int:
    hash = 0
    for byte in message:
        hash = (hash + byte) % 0xFFFF  # Ensure it's within 16-bit range at each step
    return hash


def calc_signature(hash: int, RSA_private_key: int) -> int:
    return pow(hash, RSA_private_key, DIFFIE_HELLMAN_P * DIFFIE_HELLMAN_G)


def create_msg(data: bytes) -> bytes:
    # length = len(data)
    # if length >= 2 ** (LENGTH_FIELD_SIZE * 8):
    #     return None
    # return length.to_bytes(LENGTH_FIELD_SIZE, "big") + data.encode()
    return len(data).to_bytes(LENGTH_FIELD_SIZE, "big") + data


import socket


def get_msg(my_socket: socket) -> tuple[bool, str]:
    length_field = my_socket.recv(LENGTH_FIELD_SIZE)
    if len(length_field) < LENGTH_FIELD_SIZE:
        return False, None  # Error: incomplete length field
    
    length = int.from_bytes(length_field, "big")
    message = my_socket.recv(length)
    return True, message.decode() if message else None


def is_prime(n: int) -> bool:
    """Check if a number is prime"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6

    return True


def check_RSA_public_key(totient, public_key):
    # Check if the key is prime
    if not is_prime(public_key):
        print("Public key is not prime")
        return False

    # Check if the key is smaller than the totient
    if public_key >= totient:
        print("Public key is greater than or equal to totient")
        return False

    # Check if the totient is not divisible by the key
    if totient % public_key == 0:
        print("Totient is divisible by public key")
        return False

    return True


def get_RSA_private_key(p, q, public_key):
    totient = (p - 1) * (q - 1)
    if not check_RSA_public_key(totient, public_key):
        print("Invalid RSA public key")
        return None

    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

    _, private_key, _ = extended_gcd(public_key, totient)
    return private_key % totient
