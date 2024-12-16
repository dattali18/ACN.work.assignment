import socket
import protocol


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect(("127.0.0.1", protocol.PORT))

    # Diffie Hellman
    # 1 - choose private key
    private_key = protocol.diffie_hellman_choose_private_key()
    # 2 - calc public key
    public_key = protocol.diffie_hellman_calc_public_key(private_key)
    # 3 - interact with server and calc shared secret
    my_socket.send(public_key.to_bytes(2, "big"))
    other_side_public = int.from_bytes(my_socket.recv(2), "big")
    shared_secret = protocol.diffie_hellman_calc_shared_secret(
        other_side_public, private_key
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
    # Exchange RSA public keys with server
    my_socket.send(RSA_public_key.to_bytes(4, "big"))
    server_RSA_public_key = int.from_bytes(my_socket.recv(4), "big")

    while True:
        user_input = input("Enter command\n")
        # Add MAC (signature)
        # 1 - calc hash of user input
        user_input_hash = protocol.calc_hash(user_input.encode())
        # 2 - calc the signature
        signature = protocol.calc_signature(user_input_hash, RSA_private_key)

        # Encrypt
        # apply symmetric encryption to the user's input
        encrypted_message = protocol.symmetric_encryption(
            user_input.encode(), shared_secret
        )

        # Send to server
        # Combine encrypted user's message to MAC, send to server
        msg = protocol.create_msg(encrypted_message + str(signature).encode())
        my_socket.send(msg)

        if user_input == "EXIT":
            break

        # Receive server's message
        valid_msg, message = protocol.get_msg(my_socket)
        if not valid_msg:
            print("Something went wrong with the length field")

        # Check if server's message is authentic
        # 1 - separate the message and the MAC
        # decode the message and the MAC
        message = message.decode()
        encrypted_message, received_signature = message[:-4], int(message[-4:])
        # 2 - decrypt the message
        decrypted_message = protocol.symmetric_encryption(
            encrypted_message.encode(), shared_secret
        )
        # 3 - calc hash of message
        server_message_hash = protocol.calc_hash(decrypted_message)
        # 4 - use server's public RSA key to decrypt the MAC and get the hash
        decrypted_signature = pow(
            received_signature,
            server_RSA_public_key,
            protocol.DIFFIE_HELLMAN_P * protocol.DIFFIE_HELLMAN_G,
        )
        # 5 - check if both calculations end up with the same result
        if server_message_hash == decrypted_signature:
            print("Server's message is authentic:", decrypted_message.decode())
        else:
            print("Server's message is not authentic")

    print("Closing\n")
    my_socket.close()


if __name__ == "__main__":
    main()
