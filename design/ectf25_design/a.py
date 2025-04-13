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

def format_bytes(base64_str):
    raw = base64.b64decode(base64_str)
    return ', '.join(f'0x{b:02x}' for b in raw), len(raw)

def format_pem(pem_str):
    lines = [line for line in pem_str.splitlines() if not line.startswith("-----")]
    raw = base64.b64decode(''.join(lines))
    return ', '.join(f'0x{b:02x}' for b in raw), len(raw)

def write_secrets_struct(secrets: bytes, header_path: Path):
    data = json.loads(secrets)

    struct_lines = [
        "// Auto-generated secrets header",
        "#ifndef SECRETS_H",
        "#define SECRETS_H",
        "#include <stdint.h>",
        "",
        "typedef struct {",
        "    uint8_t root_key[32];",
        "    uint8_t subscription_key[32];",
        "",
        "    uint8_t encoder_private_key[<ENC_LEN>];",
        "    uint8_t encoder_public_key[<ENCPUB_LEN>];",
        "    uint8_t decoder_private_key[<DEC_LEN>];",
        "    uint8_t decoder_public_key[<DECPUB_LEN>];",
        "    uint8_t signature_private_key[<SIGPRIV_LEN>];",
        "    uint8_t signature_public_key[<SIGPUB_LEN>];",
        "",
        f"    uint8_t channel_keys[{len(data['channel_keys'])}][32];",
        f"    int channel_ids[{len(data['channels'])}];",
        "} secrets_t;",
        "",
        "static const secrets_t embedded_secrets = {"
    ]

    root_key, _ = format_bytes(data["root_key"])
    subscription_key, _ = format_bytes(data["subscription_key"])

    encoder_priv, enc_len = format_pem(data["encoder_private_key"])
    encoder_pub, encpub_len = format_pem(data["encoder_public_key"])
    decoder_priv, dec_len = format_pem(data["decoder_private_key"])
    decoder_pub, decpub_len = format_pem(data["decoder_public_key"])
    sig_priv, sigpriv_len = format_pem(data["signature_private_key"])
    sig_pub, sigpub_len = format_pem(data["signature_public_key"])

    struct_lines.extend([
        f"    .root_key = {{{root_key}}},",
        f"    .subscription_key = {{{subscription_key}}},",
        f"    .encoder_private_key = {{{encoder_priv}}},",
        f"    .encoder_public_key = {{{encoder_pub}}},",
        f"    .decoder_private_key = {{{decoder_priv}}},",
        f"    .decoder_public_key = {{{decoder_pub}}},",
        f"    .signature_private_key = {{{sig_priv}}},",
        f"    .signature_public_key = {{{sig_pub}}},",
    ])

    struct_lines.append("    .channel_keys = {")
    for key in data["channel_keys"].values():
        b, _ = format_bytes(key)
        struct_lines.append(f"        {{{b}}},")
    struct_lines.append("    },")

    struct_lines.append(f"    .channel_ids = {{{', '.join(map(str, data['channels']))}}}")
    struct_lines.append("};")

    final_lines = '\n'.join(struct_lines)
    final_lines = final_lines.replace("<ENC_LEN>", str(enc_len))
    final_lines = final_lines.replace("<ENCPUB_LEN>", str(encpub_len))
    final_lines = final_lines.replace("<DEC_LEN>", str(dec_len))
    final_lines = final_lines.replace("<DECPUB_LEN>", str(decpub_len))
    final_lines = final_lines.replace("<SIGPRIV_LEN>", str(sigpriv_len))
    final_lines = final_lines.replace("<SIGPUB_LEN>", str(sigpub_len))
    final_lines += "\n\n#endif // SECRETS_H\n"

    with open(header_path, 'w') as f:
        f.write(final_lines)

def gen_secrets(channels: list[int]) -> bytes:
    root_key = os.urandom(32)
    encoder_private_key = ec.generate_private_key(ec.SECP256R1())
    encoder_public_key = encoder_private_key.public_key()

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
    decoder_private_bytes = decoder_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    decoder_public_bytes = decoder_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    signature_private_key = ec.generate_private_key(ec.SECP256R1())
    signature_public_key = signature_private_key.public_key()
    signature_private_bytes = signature_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    signature_public_bytes = signature_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    subscription_key = os.urandom(32)
    all_channels = list(set([0] + channels))
    channel_keys = {
        str(channel): base64.b64encode(os.urandom(32)).decode('utf-8')
        for channel in all_channels
    }

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
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", "-f", action="store_true",
                        help="Force creation of secrets file, overwriting existing file")
    parser.add_argument("secrets_file", type=Path,
                        help="Path to the secrets file to be created")
    parser.add_argument("channels", nargs="+", type=int,
                        help="Supported channels. Channel 0 (broadcast) is always valid")
    return parser.parse_args()

def main():
    args = parse_args()
    secrets = gen_secrets(args.channels)

    if args.secrets_file.exists() and not args.force:
        logger.error(f"Secrets file {str(args.secrets_file.absolute())} already exists. Use --force to overwrite")
        return

    if not args.secrets_file.parent.exists():
        logger.debug(f"Parent directory {str(args.secrets_file.parent.absolute())} does not exist")
        args.secrets_file.parent.mkdir(parents=True)

    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)

    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")

    header_path = args.secrets_file.with_suffix(".h")
    write_secrets_struct(secrets, header_path)
    logger.success(f"Wrote secrets struct to {str(header_path.absolute())}")

if __name__ == "__main__":
    main()
