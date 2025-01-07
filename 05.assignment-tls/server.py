"""Encrypted socket server implementation
   Author:
   Date:
"""

import socket
import protocol

SERVER_RSA_P = 2833
SERVER_RSA_Q = 2039
CLIENT_RSA_P = 7681  # Add this line
CLIENT_RSA_Q = 1913  # Add this line


def create_server_rsp(cmd: bytes) -> bytes:
    """Based on the command, create a proper response"""
    return b"Server response: " + cmd


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", protocol.PORT))
    server_socket.listen()
    print("Server is up and running")
    (client_socket, client_address) = server_socket.accept()
    print("Client connected")

    # print("Starting Diffie Hellman Key Exchange")

    # Diffie Hellman
    diffie_private_key = protocol.diffie_hellman_choose_private_key()
    diffie_public_key = protocol.diffie_hellman_calc_public_key(diffie_private_key)

    # Get the client's public key
    client_public_key = int(client_socket.recv(1024).decode())
    # print(f"Client Public Key: {client_public_key}")

    # Send the server's public key
    client_socket.send(str(diffie_public_key).encode())
    # print(f"Server Public Key: {diffie_public_key}")

    # Calculate shared secret
    shared_secret = protocol.diffie_hellman_calc_shared_secret(
        client_public_key, diffie_private_key
    )

    # Print the keys for testing
    # print(f"Diffie Hellman Public Key: {diffie_public_key}")
    # print(f"Diffie Hellman Private Key: {diffie_private_key}")
    # print(f"Shared Secret: {shared_secret}")

    # print("Starting RSA Key Exchange")

    # RSA
    rsa_public_key = 65537
    rsa_private_key = protocol.get_RSA_private_key(
        SERVER_RSA_P, SERVER_RSA_Q, rsa_public_key
    )

    # Wait for the client to send its public key
    client_rsa_public_key = int(client_socket.recv(1024).decode())

    # Send the server's public key
    client_socket.send(str(rsa_public_key).encode())

    # Print all the keys for testing
    # print(f"RSA Public Key: {rsa_public_key}")
    # print(f"RSA Private Key: {rsa_private_key}")
    # print(f"Client RSA Public Key: {client_rsa_public_key}")

    while True:
        # Receive client's message
        valid_msg, message = protocol.get_msg(client_socket)
        if not valid_msg:
            print("Something went wrong with the length field")
            break

        # Check if client's message is authentic
        encrypted_message, received_signature = (
            message[: -protocol.MAC_LENGTH],
            message[-protocol.MAC_LENGTH :],
        )

        # print(f"Encrypted message: {encrypted_message}")
        # print(f"Received signature: {received_signature}")

        # Convert to int
        received_signature_int = int.from_bytes(received_signature, "big")
        # print(f"Received signature (int): {received_signature_int}")

        # Decrypt the message
        decrypted_message = protocol.symmetric_decryption(
            encrypted_message, shared_secret
        )
        # print(f"Decrypted message: {decrypted_message}")

        # Calculate hash of message
        message_hash = protocol.calc_hash(decrypted_message)
        # print(f"Message Hash: {message_hash}")

        # Verify the signature
        decrypted_signature = pow(
            received_signature_int, client_rsa_public_key, CLIENT_RSA_P * CLIENT_RSA_Q
        )
        # print(f"Decrypted signature: {decrypted_signature}")
        # print(f"Calculated hash: {message_hash}")
        # print(f"RSA modulus: {CLIENT_RSA_P * CLIENT_RSA_Q}")
        # print(f"Client's public key: {client_rsa_public_key}")

        if decrypted_signature == message_hash:
            # print("Client's message is authentic")
            # print the message
            print(f"Client: {decrypted_message}")
        else:
            print(
                f"Client's message is not authentic. Expected {message_hash}, got {decrypted_signature}"
            )

        if decrypted_message.strip() == "EXIT":
            print("Client requested to exit. Closing connection.")
            break

        # Create response
        response = create_server_rsp(decrypted_message.encode("latin1"))
        encrypted_message = protocol.symmetric_encryption(
            response.decode("latin1"), shared_secret
        )
        response_hash = protocol.calc_hash(response.decode("latin1"))
        signature = protocol.calc_signature(
            response_hash, rsa_private_key, SERVER_RSA_P, SERVER_RSA_Q
        )
        combined_message = encrypted_message + signature.to_bytes(
            protocol.MAC_LENGTH, "big"
        )

        # print(f"Server response hash: {response_hash}")
        # print(f"Server signature: {signature}")

        msg = protocol.create_msg(combined_message)

        try:
            client_socket.send(msg)
        except BrokenPipeError:
            print("Client has disconnected. Closing server.")
            break

    print("Closing\n")
    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    main()
