import json
import base64
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def decrypt_subscription_file(subscription_path: str, secrets_path: str):
    # Load encrypted subscription
    with open(subscription_path, "rb") as f:
        data = f.read()

    print(data)
    iv = data[:16]
    print(iv)
    encrypted_data = data[16:]
    print(encrypted_data)

    # Load secrets
    with open(secrets_path, "r") as f:
        secrets = json.load(f)

    subscription_key = base64.b64decode(secrets["subscription_key"])
    print("subkey", subscription_key)
    print("subkey len", len(subscription_key))
    print(secrets["decoder_private_key"])
    

    # Decrypt using AES-CBC
    cipher = Cipher(algorithms.AES(subscription_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    print("\npadded data", padded_data)
    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    subscription_data = unpadder.update(padded_data) + unpadder.finalize()
    print(subscription_data)

    # Unpack structure: <IQQI
    decoder_id, start_time, end_time, channel = struct.unpack("<IQQI", subscription_data)

    print("Decrypted Subscription Contents:")
    print(f"  Decoder ID : {decoder_id}")
    print(f"  Start Time : {start_time}")
    print(f"  End Time   : {end_time}")
    print(f"  Channel    : {channel}")


if __name__ == "__main__":
    # Example usage — replace with your actual paths:
    decrypt_subscription_file("/home/hrishesh/Desktop/ectf/2025-ectf-insecure-example/latest_sub.sub", 
                                "/home/hrishesh/Desktop/ectf/2025-ectf-insecure-example/secrets/_secrets.json")
