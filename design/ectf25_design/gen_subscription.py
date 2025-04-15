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
import struct
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac

from loguru import logger


def gen_subscription(
    secrets: bytes, device_id: int, start: int, end: int, channel: int
) -> bytes:
    """Generate the contents of a subscription.

    The output of this will be passed to the Decoder using ectf25.tv.subscribe

    :param secrets: Contents of the secrets file generated by ectf25_design.gen_secrets
    :param device_id: Device ID of the Decoder
    :param start: First timestamp the subscription is valid for
    :param end: Last timestamp the subscription is valid for
    :param channel: Channel to enable
    """
    # Load the json of the secrets file
    secrets_data = json.loads(secrets)
    
    # Verify the channel is valid
    if channel != 0 and channel not in secrets_data["channels"]:
        raise ValueError(f"Channel {channel} is not a valid channel")
    
    # Get the subscription key from secrets
    subscription_key = base64.b64decode(secrets_data["subscription_key"])
    # Get the channel key for the requested channel
    channel_key = base64.b64decode(secrets_data["channel_keys"][str(channel)])
    
    # Create the subscription update packet
    subscription_data = struct.pack("<IQQI", device_id, start, end, channel)
    
    # Add the channel key to the subscription data..why 
    # subscription_data += channel_key , ik its a good idea to send key during subscription only...but trying to avoid playing with keys outside build time
    
    # Pad the data to match the block size of AES
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(subscription_data) + padder.finalize()
    
    # Generate a random IV
    iv = os.urandom(16)
    
    # Encrypt the padded data using AES-CBC with the subscription key
    cipher = Cipher(algorithms.AES(subscription_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine IV and encrypted data
    return iv + encrypted_data


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of subscription file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=argparse.FileType("rb"),
        help="Path to the secrets file created by ectf25_design.gen_secrets",
    )
    parser.add_argument("subscription_file", type=Path, help="Subscription output")
    parser.add_argument(
        "device_id", type=lambda x: int(x, 0), help="Device ID of the update recipient."
    )
    parser.add_argument(
        "start", type=lambda x: int(x, 0), help="Subscription start timestamp"
    )
    parser.add_argument("end", type=int, help="Subscription end timestamp")
    parser.add_argument("channel", type=int, help="Channel to subscribe to")
    return parser.parse_args()


def main():
    """Main function of gen_subscription

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    subscription = gen_subscription(
        args.secrets_file.read(), args.device_id, args.start, args.end, args.channel
    )

    # Print the generated subscription for your own debugging
    # Attackers will NOT have access to the output of this (although they may have
    # subscriptions in certain scenarios), but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated subscription: {subscription}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote subscription to {str(args.subscription_file.absolute())}")


if __name__ == "__main__":
    main()
