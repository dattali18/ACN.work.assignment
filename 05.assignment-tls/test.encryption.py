# this file is a test unit for the encryption function in the protocol.py file

import protocol


def test_symmetric_encryption():
    key = 0x42
    data = "\"Hello, world! My name is Daniel\""
    print(f"Data: {data}")
    encrypted_data = protocol.symmetric_encryption(data, key)
    print(f"Encrypted data: {encrypted_data}")

    decrypted_data = protocol.symmetric_decryption(encrypted_data, key)
    print(f"Decrypted data: {decrypted_data}")

    assert data == decrypted_data
    print("Test passed")


def test_decrypt():
    input = "EXIT"
    shared = 2746
    encrypted = protocol.symmetric_encryption(input, shared)
    print(f"Encrypted: {encrypted}")
    decrypted = protocol.symmetric_decryption(encrypted, shared)
    print(f"Decrypted: {decrypted}")

if __name__ == "__main__":
    print("Running the test")
    test_decrypt()


# Run the test with the following command: python test.encryption.py
