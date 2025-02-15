"""
protocol.py - Protocol implementation for multi-user chat
Author: Daniel Attali 328780879
Date: 17/11/2024
"""

LENGTH_FIELD_SIZE = 2
PORT = 8820

# Supported commands
VALID_COMMANDS = ["NAME", "GET_NAMES", "MSG", "BLOCK", "EXIT"]


def check_cmd(data):
    """
    Check if the command is valid according to the protocol.
    """
    parts = data.split(" ", 1)
    command = parts[0]
    return command in VALID_COMMANDS


def create_msg(data):
    """
    Create a valid protocol message with a length field.
    """
    length = str(len(data)).zfill(LENGTH_FIELD_SIZE)
    return f"{length}{data}"


def get_msg(my_socket):
    """
    Extract and validate a message from the socket.
    Returns (is_valid, message).
    """
    try:
        # Receive length field
        length_field = my_socket.recv(LENGTH_FIELD_SIZE).decode()
        if not length_field.isdigit():
            return False, "Error: Invalid length field"

        # Receive the rest of the message
        length = int(length_field)
        message = my_socket.recv(length).decode()
        return True, message
    except Exception as e:
        return False, f"Error: {str(e)}"
