
// #if CRYPTO_EXAMPLE
// #ifndef ECTF_CRYPTO_H
// #define ECTF_CRYPTO_H
#pragma once 

#include <stdint.h>
#include <stddef.h>  
#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/types.h" // Ensure ecc_key is fully defined

// #include "wolfssl/wolfcrypt/ecdsa.h" nothing like this
#include "wolfssl/wolfcrypt/asn_public.h"  // Needed for KeyPemToDer
#include "wolfssl/wolfcrypt/aes.h"
// #include "host_messaging.h" // For msg_type_t

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
// #define AES_BLOCK_SIZE 16 lol already decaled the exact same way in wolfssl/wolfcrypt/aes.h
#define SIGNATURE_LENGTH 64

/**
 * @brief Decrypt the received frame using ECDH (Elliptic Curve Diffie-Hellman) and AES.
 * 
 * @param private_key_pem The private key in PEM format.
 * @param public_key_pem The public key of the peer in PEM format.
 * @param iv_32 32-byte initialization vector used in AES encryption.
 * @param received_frame The encrypted message (without signature).
 * @param frame_len The length of the encrypted message.
 * @param decrypted_output Buffer for storing decrypted data.
 * 
 * @return 0 on success, non-zero on failure.
 */
int ecdh_decrypt(
    const char *private_key_pem,
    const char *public_key_pem,
    const uint8_t *iv_32,
    const uint8_t *received_frame,
    size_t frame_len,
    uint8_t *decrypted_output
);

/**
 * @brief Verify the signature of the message using the public key.
 * 
 * @param message The message to verify.
 * @param message_len The length of the message.
 * @param signature The signature to verify.
 * @param signature_len The length of the signature.
 * @param public_key The public key in PEM format.
 * 
 * @return 0 if the signature is valid, non-zero if invalid.
 */
int verify_signature(
    unsigned char *message,
    size_t message_len,
    unsigned char *signature,
    size_t signature_len,
    const char *public_key
);

/**
 * @brief Decrypt data using AES with the provided AES key and IV.
 * 
 * @param aes_key The AES decryption key.
 * @param iv_16 The 16-byte IV used in AES decryption.
 * @param encrypted_data The encrypted data to decrypt.
 * @param encrypted_len The length of the encrypted data.
 * @param decrypted_output The buffer for storing the decrypted output.
 * 
 * @return 0 on success, non-zero on failure.
 */
int aes_decrypt(
    const uint8_t *aes_key,
    const uint8_t *iv_16,
    const uint8_t *encrypted_data,
    size_t encrypted_len,
    uint8_t *decrypted_output
);

// #endif // CRYPTO_EXAMPLE
// #endif // ECTF_CRYPTO_H
