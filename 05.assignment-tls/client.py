"""Encrypted socket client implementation
   Author:
   Date:
"""

import socket
import protocol

CLIENT_RSA_P = 7681
CLIENT_RSA_Q = 1913
SERVER_RSA_P = 2833  # Add this line
SERVER_RSA_Q = 2039  # Add this line


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect(("127.0.0.1", protocol.PORT))

    print("Connected to server")

    # print("Starting Diffie Hellman Key Exchange")
    # Diffie Hellman
    diffie_private_key = protocol.diffie_hellman_choose_private_key()
    diffie_public_key = protocol.diffie_hellman_calc_public_key(diffie_private_key)

    # Send public key to server
    my_socket.send(str(diffie_public_key).encode())
    # print(f"Client Public Key: {diffie_public_key}")

    # Wait for the server's public key
    server_public_key = int(my_socket.recv(1024).decode())
    # print(f"Server Public Key: {server_public_key}")

    # Calculate shared secret
    shared_secret = protocol.diffie_hellman_calc_shared_secret(
        server_public_key, diffie_private_key
    )

    # print(f"Diffie Hellman Public Key: {diffie_public_key}")
    # print(f"Diffie Hellman Private Key: {diffie_private_key}")
    # print(f"Shared Secret: {shared_secret}")

    # print("Starting RSA Key Exchange")

    # RSA
    rsa_public_key = 65537
    rsa_private_key = protocol.get_RSA_private_key(
        CLIENT_RSA_P, CLIENT_RSA_Q, rsa_public_key
    )

    # Exchange RSA public keys with server
    my_socket.send(str(rsa_public_key).encode())
    server_rsa_public_key = int(my_socket.recv(1024).decode())

    # print(f"RSA Public Key: {rsa_public_key}")
    # print(f"RSA Private Key: {rsa_private_key}")
    # print(f"Server RSA Public Key: {server_rsa_public_key}")

    while True:
        user_input = input("Enter command: ")
        # print(f"User: {user_input}")

        # Calculate hash of user input
        user_input_hash = protocol.calc_hash(user_input)
        # print(f"User Hash: {user_input_hash}")

        # Calculate the signature
        signature = protocol.calc_signature(
            user_input_hash, rsa_private_key, CLIENT_RSA_P, CLIENT_RSA_Q
        )
        # print(f"Signature: {signature}")

        # Encrypt the user's input
        encrypted_message = protocol.symmetric_encryption(user_input, shared_secret)
        # print(f"Encrypted Message: {encrypted_message}")

        # Combine encrypted message and signature
        combined_message = encrypted_message + signature.to_bytes(
            protocol.MAC_LENGTH, "big"
        )
        # print(f"Combined Message: {combined_message}")
        # print(f"Combined Message (hex): {combined_message.hex()}")

        # Send to server
        msg = protocol.create_msg(combined_message)
        my_socket.send(msg)

        if user_input == "EXIT":
            break

        # Receive server's message
        valid_msg, message = protocol.get_msg(my_socket)
        if not valid_msg:
            print("Something went wrong with the length field")
            break

        # Check if server's message is authentic
        encrypted_message, received_signature = (
            message[: -protocol.MAC_LENGTH],
            message[-protocol.MAC_LENGTH :],
        )

        # Decrypt the message
        decrypted_message = protocol.symmetric_decryption(
            encrypted_message, shared_secret
        )

        # Calculate hash of received message
        received_hash = protocol.calc_hash(decrypted_message)

        # Convert received signature to int
        received_signature = int.from_bytes(received_signature, "big")
        # print(f"Received signature (int): {received_signature}")

        # Verify the signature
        decrypted_signature = pow(
            received_signature, server_rsa_public_key, SERVER_RSA_P * SERVER_RSA_Q
        )
        # print(f"Decrypted signature: {decrypted_signature}")
        # print(f"Calculated hash: {received_hash}")
        # print(f"RSA modulus: {SERVER_RSA_P * SERVER_RSA_Q}")
        # print(f"Server's public key: {server_rsa_public_key}")

        if received_hash == decrypted_signature:
            # print("Server's message is authentic")
            # print the message
            print(f"Server: {decrypted_message}")
        else:
            print(
                f"Server's message is not authentic. Expected {received_hash}, got {decrypted_signature}"
            )
            break

        # Print server's message
        # print(f"Server: {decrypted_message}")

    print("Closing\n")
    my_socket.close()


if __name__ == "__main__":
    main()
