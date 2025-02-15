"""
server.py - Multi-user chat server
Author: Daniel Attali 328780879
Date: 18/11/2024
"""

import socket
import select
import protocol

# Server configuration
SERVER_PORT = 8888
SERVER_IP = "0.0.0.0"


blocked_users = {}  # dictionary to store blocked users and their blocked users


# for example A: [B, C] means A has blocked B and C
def handle_name_command(parts, current_socket, clients_names):
    if len(parts) < 2:
        return "Error: Invalid NAME command", None
    name = parts[1]
    # CHECK IF THE NAME IS BROADCAST AND TELL THE CLIENT THAT IT IS RESERVED
    if name == "BROADCAST":
        return "Error: Name is reserved", None
    if name in clients_names:
        return "Error: Name already taken", None
    clients_names[name] = current_socket
    return f"Welcome, {name}!", None


def handle_get_names_command(clients_names):
    return "Connected clients: " + ", ".join(clients_names.keys()), None


def handle_msg_command(parts, current_socket, clients_names, blocked_users):
    if len(parts) < 3:
        return "Error: Invalid MSG command", None
    target_name = parts[1]
    message = parts[2]
    sender_name = next(
        (name for name, sock in clients_names.items() if sock == current_socket),
        "Unknown",
    )

    if target_name == "BROADCAST":
        return f"{sender_name}: {message}", "BROADCAST"
    elif target_name in clients_names:
        if sender_name not in blocked_users.get(target_name, []):
            return f"{sender_name}: {message}", clients_names[target_name]
        else:
            return f"Error: Communication with {target_name} is blocked.", None
    return f"Error: Client {target_name} not found", None


def handle_block_command(parts, current_socket, clients_names, blocked_users):
    if len(parts) < 2:
        return "Error: Invalid BLOCK command", None
    target_name = parts[1]
    sender_name = next(
        (name for name, sock in clients_names.items() if sock == current_socket),
        "Unknown",
    )
    if target_name in clients_names:
        if sender_name not in blocked_users:
            blocked_users[sender_name] = []
        if target_name not in blocked_users[sender_name]:
            blocked_users[sender_name].append(target_name)
        return f"{sender_name} has blocked {target_name}", None
    return f"Error: Client {target_name} not found", None


def handle_client_request(current_socket, clients_names, data):
    """
    Handles client requests and returns the appropriate response and destination socket.
    """
    parts = data.split(" ", 2)
    command = parts[0]

    if command == "NAME":
        return handle_name_command(parts, current_socket, clients_names)
    elif command == "GET_NAMES":
        # and check that there is no message after the command
        if len(parts) > 1:
            return "Error: Invalid GET_NAMES command", None
        return handle_get_names_command(clients_names)
    elif command == "MSG":
        return handle_msg_command(parts, current_socket, clients_names, blocked_users)
    elif command == "BLOCK":
        return handle_block_command(parts, current_socket, clients_names, blocked_users)
    elif command == "EXIT":
        return "Goodbye!", current_socket  # Indicate the client will be removed
    else:
        return "Error: Unknown command", None


def print_client_sockets(client_sockets):
    """
    Prints the list of currently connected client sockets.
    """
    print("Connected clients:")
    for client_socket in client_sockets:
        print(f"\t{client_socket.getpeername()}")


def accept_new_client(server_socket, client_sockets, clients_names):
    """
    Accepts a new client connection and adds it to the list of client sockets.
    """
    client_socket, client_address = server_socket.accept()
    print(f"New connection from {client_address}")
    client_sockets.append(client_socket)
    print_client_sockets(client_sockets)


def handle_disconnected_client(current_socket, client_sockets, clients_names):
    """
    Handles a client disconnection, removes it from the list of sockets and names.
    """
    print("Client disconnected")
    client_sockets.remove(current_socket)
    current_socket.close()
    # Remove client from name dictionary if it had a name
    disconnected_name = next(
        (name for name, sock in clients_names.items() if sock == current_socket), None
    )
    if disconnected_name:
        del clients_names[disconnected_name]


def process_client_data(
    current_socket, client_sockets, clients_names, messages_to_send
):
    """
    Processes data received from a client and queues responses.
    """
    data = protocol.get_msg(current_socket)
    if not data[0]:  # Invalid or disconnected client
        handle_disconnected_client(current_socket, client_sockets, clients_names)
    else:
        print(f"Received data: {data[1]}")
        response, dest_socket = handle_client_request(
            current_socket, clients_names, data[1]
        )
        if dest_socket == "BROADCAST":
            for client_sock in client_sockets:
                if client_sock != current_socket:  # Skip sender
                    recipient_name = next(
                        (
                            name
                            for name, sock in clients_names.items()
                            if sock == client_sock
                        ),
                        None,
                    )
                    # Ensure the recipient has not blocked the sender
                    sender_name = next(
                        (
                            name
                            for name, sock in clients_names.items()
                            if sock == current_socket
                        ),
                        "Unknown",
                    )
                    if recipient_name and sender_name not in blocked_users.get(
                        recipient_name, []
                    ):
                        messages_to_send.append((client_sock, response))
        elif dest_socket:
            messages_to_send.append((dest_socket, response))
        else:
            messages_to_send.append((current_socket, response))


def send_pending_messages(messages_to_send, ready_to_write):
    """
    Sends messages to clients that are ready to receive them.
    """
    for message in messages_to_send:
        dest_socket, data = message
        if dest_socket in ready_to_write:
            try:
                response = protocol.create_msg(data)
                dest_socket.send(response.encode())
                messages_to_send.remove(message)
            except Exception as e:
                print(f"Error sending message: {e}")
                dest_socket.close()


def main():
    # Set up the server
    print("Setting up server...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen()
    print(f"Server is listening on {SERVER_IP}:{SERVER_PORT}")

    # Initialize data structures
    client_sockets = []
    messages_to_send = []
    clients_names = {}

    try:
        while True:
            # Use `select` to monitor sockets
            read_list = client_sockets + [server_socket]
            ready_to_read, ready_to_write, _ = select.select(
                read_list, client_sockets, []
            )

            # Accept new connections
            if server_socket in ready_to_read:
                accept_new_client(server_socket, client_sockets, clients_names)

            # Handle data from clients
            for current_socket in ready_to_read:
                if current_socket is not server_socket:
                    process_client_data(
                        current_socket, client_sockets, clients_names, messages_to_send
                    )

            # Send pending messages
            send_pending_messages(messages_to_send, ready_to_write)

    finally:
        print("Shutting down server...")
        for sock in client_sockets:
            sock.close()
        server_socket.close()


if __name__ == "__main__":
    main()
