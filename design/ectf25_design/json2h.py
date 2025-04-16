import json
import base64
import sys
import os
from pathlib import Path


# ALL_CHANNELS_EXCEPT_0 = [ 1, 2, 3, 4, 5, 6, 7, 8]

def json_to_c_header(secrets, header_file):
    """Convert a JSON secrets file to a C header file"""
    
    # Read the JSON file
    # with open(json_file, 'r') as f:
    #     secrets = json.load(f)
    
    # Start building the header content
    header = """
/*
 * Auto-generated secrets header file
 * WARNING: Keep this file secure!
 */

#ifndef SECRETS_H
#define SECRETS_H

#include <stdint.h>

/* Channel configuration */
"""
    
    # Add channels
    # channels = secrets.get("channels", []) 
    
    # header += f"#define NUM_CHANNELS_EXCEPT_0 {len(ALL_CHANNELS_EXCEPT_0)}\n"  # including channel 0
    # header += f"static const uint8_t VALID_CHANNELS[] = {{0, {', '.join(str(c) for c in ALL_CHANNELS_EXCEPT_0)}}};\n\n"
    # VALU = {{0, {', '.join(str(c) for c in ALL_CHANNELS_EXCEPT_0)}}}
    # header += f"static const uint8_t VALID_CHANNELS[] = {VALU};\n\n"
    
    # header += f"static const uint8_t VALID_CHANNELS[ ] = {" + f"{', '.join(str(c) for c in secrets["channels"])}"+ "};\n\n"
    header += "static const uint8_t VALID_CHANNELS[] = {" + ", ".join(map(str, secrets["channels"])) + "};\n\n"

    # Add root key
    root_key_b64 = secrets.get("root_key", "")
    root_key = base64.b64decode(root_key_b64)
    header += "/* Root key */\n"
    header += f"static const uint8_t ROOT_KEY[{len(root_key)}] = {{\n    "
    header += ", ".join(f"0x{b:02x}" for b in root_key)
    header += "\n};\n\n"
    
    # Add subscription key
    sub_key_b64 = secrets.get("subscription_key", "")
    sub_key = base64.b64decode(sub_key_b64)
    header += "/* Subscription key */\n"
    header += f"static const uint8_t SUBSCRIPTION_KEY[{len(sub_key)}] = {{\n    "
    header += ", ".join(f"0x{b:02x}" for b in sub_key)
    header += "\n};\n\n"
    
    # Add channel keys
    header += "/* Channel keys */\n"
    channel_keys = secrets.get("channel_keys", {})
    for channel, key_b64 in channel_keys.items():
        key = base64.b64decode(key_b64)
        header += f"static const uint8_t CHANNEL_{channel}_KEY[{len(key)}] = {{\n    "
        header += ", ".join(f"0x{b:02x}" for b in key)
        header += "\n};\n"
    
    # Add ECDSA keys
    # For PEM keys, we'll create string constants
    header += "\n/* Encoder public key (PEM format) */\n"
    header += "static const char ENCODER_PUBLIC_KEY[] = \n"
    
    # Format multi-line string for C
    encoder_public_key = secrets.get("encoder_public_key", "").strip()
    for line in encoder_public_key.split('\n'):
        header += f'    "{line}\\n"\n'
    header += ";\n\n"
    
    # Add decoder private key (PEM format)
    header += "/* Decoder private key (PEM format) */\n"
    header += "static const char DECODER_PRIVATE_KEY[] = \n"
    decoder_private_key = secrets.get("decoder_private_key", "").strip()
    for line in decoder_private_key.split('\n'):
        header += f'    "{line}\\n"\n'
    header += ";\n\n"
    
    # Add signature public key (PEM format)
    header += "/* Signature public key (PEM format) */\n"
    header += "static const char SIGNATURE_PUBLIC_KEY[] = \n"
    signature_public_key = secrets.get("signature_public_key", "").strip()
    for line in signature_public_key.split('\n'):
        header += f'    "{line}\\n"\n'
    header += ";\n\n"
    
    # Close the header
    header += "#endif /* SECRETS_H */\n"
    
    # Write the header file
    with open(header_file, 'w') as f:
        f.write(header)
    
    print(f"Converted to C header file {header_file}")


def main():
    # if len(sys.argv) < 3:
    #     print(f"Usage: {sys.argv[0]} input.json output.h")
    #     sys.exit(1)
    
    json_file = "secrets/secrets.json"
    header_file = "decoder/inc/secrets.h"
    
    # Read the JSON file
    # with open(json_file, 'r') as f:
    #     secrets = json.load(f)
    # json_to_c_header(secrets=secrets, header_file=header_file)

if __name__ == "__main__":
    main()