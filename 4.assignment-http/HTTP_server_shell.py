# Ex 4 - HTTP Server Shell
# Author: Daniel Attali - 328780879

import os
import sys
from typing import Tuple

WEBROOT_DIR = os.path.join(os.path.dirname(__file__), "webroot")
INDEX_FILE = os.path.join(WEBROOT_DIR, "index.html")
JS_DIR = os.path.join(WEBROOT_DIR, "js")
CSS_DIR = os.path.join(WEBROOT_DIR, "css")
IMG_DIR = os.path.join(WEBROOT_DIR, "imgs")
UPLOAD_DIR = os.path.join(WEBROOT_DIR, "uploads")

# MARK: MOVED_RESOURCES dictionary for the grader to test
MOVED_RESOURCES = {"/old.html": "/new.html"}

DEFAULT_RESOURCES = {"": "index.html", "/": "index.html"}
MIME_TYPES = {
    ".html": "text/html",
    ".css": "text/css",
    ".js": "application/javascript",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
}

# TO DO: import modules
import socket

# TO DO: set constants
IP = "0.0.0.0"
PORT = 80
SOCKET_TIMEOUT = 0.5
# REDIRECTION_DICTIONARY = {old_resource_name: new_resource_name} # Programmer should pick the old and new resources
FIXED_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/html; charset=ISO-8859-1\r\n\r\nhello"


def get_file_data(filename: str) -> bytes | None:
    """
    Reads the content of a file and returns it as bytes.
    Args:
        filename (str): The path to the file to be read.
    Returns:
        bytes | None: The content of the file as bytes if the file exists,
                      otherwise None if the file is not found.
    """

    try:
        with open(filename, "rb") as file:
            print(f"Reading file: {filename}")
            return file.read()
    except FileNotFoundError:
        # print(f"File not found: {filename}")
        return None


def handle_client_request_calculate_area(resource: str, socket) -> None:
    # extract the height and width from the resource string
    # calculate the area and send it back to the client

    width, height = 0, 0

    try:
        split_resource = resource.split("?")

        print(f"Split resource: {split_resource}")
        # extract the width and height from the resource string
        # take into account the parameters might be in different order
        if split_resource[1].startswith("width"):
            width = int(resource.split("width=")[1].split("&")[0])
            height = int(resource.split("height=")[1])
        else:
            height = int(resource.split("height=")[1].split("&")[0])
            width = int(resource.split("width=")[1])

        area = width * height

        print(f"Calculating area for width={width} and height={height}")

        response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(str(area))}\r\nContent-Type: text/plain\r\n\r\n{area}".encode()
        socket.send(response)
    except ValueError:
        response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".encode()
        socket.send(response)
        return


def handle_client_request_calculate_next(resource: str, socket) -> None:
    # extract the number from the resource string
    # calculate the next number and send it back to the client

    num = 0

    try:
        num = int(resource.split("num=")[1])
        next_num = num + 1

        print(f"Calculating next number for num={num}")

        response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(str(next_num))}\r\nContent-Type: text/plain\r\n\r\n{next_num}".encode()
        socket.send(response)
    except ValueError:
        response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".encode()
        socket.send(response)
        return


def handle_client_request(resource: str, socket) -> None:
    print(f"Handling request for resource: {resource}")

    # check if resources is '/calculate-area?height=<>&width=<>'
    # or '/calculate-next?num=1<>' and handle them in a special function

    if resource.startswith("/calculate-area"):
        handle_client_request_calculate_area(resource, socket)
        return
    elif resource.startswith("/calculate-next"):
        handle_client_request_calculate_next(resource, socket)
        return

    # check if resource is in the DEFAULT_RESOURCES dictionary
    if resource in DEFAULT_RESOURCES:
        resource = DEFAULT_RESOURCES[resource]

    # # check for potential issue with people trying to access files outside the webroot
    # for cybersecurity reasons, we should prevent users from accessing files outside the webroot
    file_path = os.path.normpath(os.path.join(WEBROOT_DIR, resource.lstrip("/")))
    if not file_path.startswith(WEBROOT_DIR):  # Prevent accessing files outside webroot
        response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".encode()
        socket.send(response)
        return

    # check if the resource is in the MOVED_RESOURCES dictionary
    if resource in MOVED_RESOURCES:
        print(f"Resource moved from {resource} to {MOVED_RESOURCES[resource]}")
        response = f"HTTP/1.1 302 Moved Permanently\r\nLocation: {MOVED_RESOURCES[resource]}\r\nContent-Length: 0\r\n\r\n".encode()
        socket.send(response)
        return

    file_data = get_file_data(file_path)

    if file_data:  # if file_data is not None
        # determine the content type based on the file extension
        end_with = file_path.split(".")[-1].lower()
        content_type = MIME_TYPES.get(f".{end_with}", "application/octet-stream")

        response = (
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(file_data)}\r\nContent-Type: {content_type}\r\n\r\n".encode()
            + file_data
        )

    else:
        print(f"Resource not found: {resource}")
        response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".encode()

    socket.send(response)


def validate_HTTP_request(request: str) -> Tuple[bool, str]:
    """
    Validates an HTTP request string.
    This function checks if the given HTTP request string is a valid HTTP/1.1 GET request.
    It splits the request into lines and extracts the method, resource, and version from the request line.
    If the method is not 'GET' or the version is not 'HTTP/1.1', it returns False and an empty string.
    If the request is valid, it returns True and the requested resource.
    Args:
        request (str): The HTTP request string to validate.
    Returns:
        Tuple[bool, str]: A tuple containing a boolean indicating whether the request is valid,
                          and the requested resource if valid, or an empty string if not.
    """
    try:
        lines = request.split("\r\n")
        method, resource, version = lines[0].split(" ")

        if method != "GET" and version != "HTTP/1.1":
            return False, ""
    except ValueError:
        return False, ""

    return True, resource


def handle_client(socket):
    print("Client connected")
    try:
        # assume the request is at most 1024 bytes long
        request = socket.recv(1024).decode()

        valid_http, resource = validate_HTTP_request(request)
        if valid_http:
            print(f"Valid request for resource: {resource}")
            handle_client_request(resource, socket)
        else:
            print("Invalid HTTP request")
            socket.send(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".encode()
            )
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        socket.close()
        print("Connection closed")


def main():
    # Open a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen()
    print("Listening for connections on port {}".format(PORT))

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"New connection received from {client_address}")
            client_socket.settimeout(SOCKET_TIMEOUT)
            handle_client(client_socket)
    except (
        KeyboardInterrupt
    ):  # gracefully shutdown the server when a keyboard interrupt is received
        print("Shutting down server")
    finally:
        server_socket.close()


if __name__ == "__main__":
    # Call the main handler function
    main()
