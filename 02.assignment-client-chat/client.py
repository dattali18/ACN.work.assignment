"""
client.py - Multi-user chat client
Author: Daniel Attali 328780879
Date: 18/11/2024
"""

import socket
import select
import msvcrt  # For non-blocking keyboard input
import protocol

# Constants
SERVER_ADDRESS = ("127.0.0.1", 8888)


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect(SERVER_ADDRESS)
    print(
        "Connected to the server. Enter commands (e.g., NAME <name>, GET_NAMES, MSG <NAME> <message>, EXIT):\n"
    )

    while True: # and check if the server is still running
        # Use `select` for non-blocking I/O
        rlist, _, _ = select.select([my_socket], [], [], 0.2)

        # Check for incoming messages
        if rlist:
            valid, response = protocol.get_msg(my_socket)
            if valid:
                print(f"\nServer: {response}")
            else:
                print(f"\nError receiving message: {response}")
                break

        # Check for user input
        if msvcrt.kbhit():
            user_input = input("> ").strip()  # Get input from the user
            if user_input:
                # Validate and send the command
                valid_cmd = protocol.check_cmd(user_input)
                if valid_cmd:
                    message = protocol.create_msg(user_input)
                    my_socket.sendall(message.encode())
                    if user_input.startswith("EXIT"):
                        print("Exiting chat...")
                        break
                else:
                    print("Invalid command. Please try again.")

    # Close the socket
    my_socket.close()
    print("Disconnected from the server.")


if __name__ == "__main__":
    main()
