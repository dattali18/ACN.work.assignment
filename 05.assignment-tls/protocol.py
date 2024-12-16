"""
Encrypted sockets implementation
   Author:Daniel Attali
   Date: 16/12/2024
"""

LENGTH_FIELD_SIZE = 2
PORT = 8820

DIFFIE_HELLMAN_P = ?
DIFFIE_HELLMAN_G = ?


def symmetric_encryption(input_data, key):
    """Return the encrypted / decrypted data
    The key is 16 bits. If the length of the input data is odd, use only the bottom 8 bits of the key.
    Use XOR method"""
    return


def diffie_hellman_choose_private_key():
    """Choose a 16 bit size private key """
    return


def diffie_hellman_calc_public_key(private_key):
    """G**private_key mod P"""
    return


def diffie_hellman_calc_shared_secret(other_side_public, my_private):
    """other_side_public**my_private mod P"""
    return


def calc_hash(message):
    """Create some sort of hash from the message
    Result must have a fixed size of 16 bits"""
    return


def calc_signature(hash, RSA_private_key):
    """Calculate the signature, using RSA alogorithm
    hash**RSA_private_key mod (P*Q)"""
    return


def create_msg(data):
    """Create a valid protocol message, with length field
    For example, if data = data = "hello world",
    then "11hello world" should be returned"""
    return


def get_msg(my_socket):
    """Extract message from protocol, without the length field
       If length field does not include a number, returns False, "Error" """
    return
    

def check_RSA_public_key(totient):
    """Check that the selected public key satisfies the conditions
    key is prime
    key < totoent
    totient mod key != 0"""
    return
    
    
def get_RSA_private_key(p, q, public_key):
    """Calculate the pair of the RSA public key.
    Use the condition: Private*Public mod Totient == 1
    Totient = (p-1)(q-1)"""
    return


