"""
Author: Krish Agrawal
Date: 2025

This source file is part of an IITI Design system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!
"""


import argparse
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os
import base64

from loguru import logger

from ectf25_design.json2h import json_to_c_header



def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents secrets file with cryptographic keys
    
    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid
    
    :returns: Contents of the secrets file
    """
    # Generate Root Key (master key for the system)
    root_key = os.urandom(32)  # 256 bits
    channels.append(0)  # Include emergency broadcast channel
    # Generate Encoder ECDSA key pair
    encoder_private_key = ec.generate_private_key(ec.SECP256R1())
    encoder_public_key = encoder_private_key.public_key()
    
    # Serialize the keys to store them
    private_bytes = encoder_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = encoder_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    decoder_private_key = ec.generate_private_key(ec.SECP256R1())
    decoder_public_key = decoder_private_key.public_key()

    # Serialize the keys to store them
    decoder_private_bytes = decoder_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    decoder_public_bytes = decoder_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Digital signature key pair
    signature_private_key = ec.generate_private_key(ec.SECP256R1())
    signature_public_key = signature_private_key.public_key()

    # Serialize the keys to store them
    signature_private_bytes = signature_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    signature_public_bytes = signature_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Generate Subscription Key
    subscription_key = os.urandom(32)  # AES-256 key
    
    # Generate Channel Keys (one for each channel including emergency channel 0)
    # all_channels = list(set([0] + channels))  # Include emergency broadcast channel
    channel_keys = {}
    ALL_CHANNELS = [0, 1, 2, 3, 4, 5, 6, 7, 8] #to get index of standard channesl right
    
    for channel in ALL_CHANNELS: #to get index of standard channesl right
        # For each channel, generate an AES-GCM key
        channel_key = os.urandom(32)  # 256-bit key
        # Store as base64 for JSON compatibility
        channel_keys[str(channel)] = base64.b64encode(channel_key).decode('utf-8')
    
    # Create the secrets object
    secrets = {
        "channels": channels,
        "root_key": base64.b64encode(root_key).decode('utf-8'),
        "encoder_private_key": private_bytes.decode('utf-8'),
        "encoder_public_key": public_bytes.decode('utf-8'),
        "decoder_private_key": decoder_private_bytes.decode('utf-8'),
        "decoder_public_key": decoder_public_bytes.decode('utf-8'),
        "signature_private_key": signature_private_bytes.decode('utf-8'),
        "signature_public_key": signature_public_bytes.decode('utf-8'),
        "subscription_key": base64.b64encode(subscription_key).decode('utf-8'),
        "channel_keys": channel_keys
    }
    
    return json.dumps(secrets).encode()


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.channels)
    secrets_header_output_path = str(args.secrets_file).split(".")[0] + ".h" #assuming .json file (not global.secrets)
    secrets_header_output_path = Path("decoder/inc/secrets.h") # + secrets_header_output_path.split("/")[1]) when gensecrets run inside ectf-folder
    print(f"secrets_header_output_path: {secrets_header_output_path}")

    # Check if the file already exists
    if args.secrets_file.exists() and not args.force:
        logger.error(
            f"Secrets file {str(args.secrets_file.absolute())} already exists. "
            "Use --force to overwrite"
        )
        return
    
    # Check if directory exists
    if not args.secrets_file.parent.exists():
        logger.debug(
            f"Parent directory {str(args.secrets_file.parent.absolute())} does not exist"
        )
        # Create the directory
        args.secrets_file.parent.mkdir(parents=True)

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)
        json_to_c_header(json.loads(secrets.decode('utf-8')), secrets_header_output_path)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
