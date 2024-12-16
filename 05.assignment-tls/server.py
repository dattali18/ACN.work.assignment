"""
Encrypted socket server implementation
   Author: Daniel Attali
   Date: 16/12/2024
"""

import socket
import protocol


def create_server_rsp(cmd):
    """Based on the command, create a proper response"""
    return "Server response"


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", protocol.PORT))
    server_socket.listen()
    print("Server is up and running")
    (client_socket, client_address) = server_socket.accept()
    print("Client connected")

    # Diffie Hellman
    # 1 - choose private key
    private_key = protocol.diffie_hellman_choose_private_key()
    # 2 - calc public key
    public_key = protocol.diffie_hellman_calc_public_key(private_key)
    # 3 - interact with client and calc shared secret
    client_public_key = int.from_bytes(client_socket.recv(2), "big")
    client_socket.send(public_key.to_bytes(2, "big"))
    shared_secret = protocol.diffie_hellman_calc_shared_secret(
        client_public_key, private_key
    )

    # RSA
    # Pick public key
    RSA_public_key = 65537  # Commonly used public key
    # Calculate matching private key
    p, q = 31337, 31357  # Example prime numbers, replace with secure primes
    RSA_private_key = protocol.get_RSA_private_key(p, q, RSA_public_key)
    if RSA_private_key is None:
        print("Failed to generate RSA private key")
        return
    # Exchange RSA public keys with client
    client_RSA_public_key = int.from_bytes(client_socket.recv(4), "big")
    client_socket.send(RSA_public_key.to_bytes(4, "big"))

    while True:
        # Receive client's message
        is_valid, message = protocol.get_msg(client_socket)
        if not message:
            print("Client disconnected")
            break

        # Separate the message and the MAC
        encrypted_message, received_signature = message[:-4], int(message[-4:])
        # Decrypt the message
        decrypted_message = protocol.symmetric_encryption(
            encrypted_message.encode(), shared_secret
        )
        # Calculate hash of the message
        client_message_hash = protocol.calc_hash(decrypted_message)
        # Use client's public RSA key to decrypt the MAC and get the hash
        decrypted_signature = pow(
            received_signature,
            client_RSA_public_key,
            protocol.DIFFIE_HELLMAN_P * protocol.DIFFIE_HELLMAN_G,
        )
        # Check if both calculations end up with the same result
        if client_message_hash == decrypted_signature:
            print("Client's message is authentic:", decrypted_message.decode())
            response = create_server_rsp(decrypted_message.decode())
        else:
            print("Client's message is not authentic")
            response = "Message authentication failed"

        # Encrypt the response
        encrypted_response = protocol.symmetric_encryption(
            response.encode(), shared_secret
        )
        # Calculate hash of the response
        response_hash = protocol.calc_hash(response.encode())
        # Calculate the signature
        signature = protocol.calc_signature(response_hash, RSA_private_key)
        # Send the response to the client
        msg = protocol.create_msg(encrypted_response.decode() + str(signature))
        client_socket.send(msg.encode())

    print("Closing connection")
    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    main()
