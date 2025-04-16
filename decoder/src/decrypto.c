
// #ifdef CRYPTO_EXAMPLE
#include "decrypto.h"

int aes_decrypt_cbc(const uint8_t *encrypted_data, size_t encrypted_data_len,
                    const uint8_t *key, const uint8_t *iv, uint8_t *decrypted_data) {
    Aes aes;
    int result;

    // Initialize AES context
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        return -1;
    }

    // Set the 256-bit AES decryption key
    result = wc_AesSetKey(&aes, key, 32, iv, AES_DECRYPTION);
    if (result != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    // Perform decryption
    result = wc_AesCbcDecrypt(&aes, decrypted_data, encrypted_data, encrypted_data_len);
    if (result != 0) {
        wc_AesFree(&aes);
        return -1;
    }

    wc_AesFree(&aes);
    return (int)encrypted_data_len;
}





/** brief Verify the signature of the message using the public key.
 * 
 * @param message The message to verify.
 * @param message_len The length of the message.
 * @param signature The signature to verify.
 * @param signature_len The length of the signature.
 * @param public_key The public key in PEM format.
 * 
 * @return 0 if the signature is valid, non-zero if invalid.
 * 
 */



// int verify_signature(
//     unsigned char *message, 
//     size_t message_len, 
//     unsigned char *signature, 
//     size_t signature_len, 
//     char *public_key)
// {

//     byte der[256];
//     word32 derSize = sizeof(der);

//     int ret = wc_KeyPemToDer((const byte *)public_key, strlen(public_key), der, derSize, NULL);
//     if (ret < 0)
//     {
//         printf("PEM to DER failed: %d\n", ret);
//         return -1;
//     }
//     derSize = ret; //bytes converted to der

//     wc_ecc_key pubKey;
//     wc_ecc_init(&pubKey);
//     ret = wc_EccPublicKeyDecode(der, NULL, &pubKey, derSize);
//     if (ret < 0)
//     {
//         printf("Key decode failed: %d\n", ret);
//         return -1;
//     }

//     // Verify the signature
//     int result;
//     ret = wc_ecc_verify(signature, signature_len, message, message_len, &result, &pubKey);

//     if (ret < 0)
//     {
//         printf("Signature verify error: %d\n", ret);
//         return -1;
//     }


//     return result;
// }


int ecdh_decrypt(
    const char *private_key_pem,   // The private key in PEM format
    const char *public_key_pem,    // The peer's public key in PEM format
    const uint8_t *iv_32,          // 32-byte IV used in AES encryption
    const uint8_t *received_frame, // The encrypted message (without signature)
    size_t frame_len,              // Length of the encrypted message
    uint8_t *decrypted_output      // Buffer for decrypted output
)
{
    int ret;
    ecc_key myKey, peerKey; //ignore the squiggly errors    
    byte derPriv[1024], derPub[1024];
    word32 derPrivSz, derPubSz;

    uint8_t shared_secret[32];
    word32 shared_len = sizeof(shared_secret);

    Aes aes;

    // Initialize ECC keys
    wc_ecc_init(&myKey);
    wc_ecc_init(&peerKey);

    // Convert private key PEM to DER format
    derPrivSz = wc_KeyPemToDer((const byte *)private_key_pem, (word32)strlen(private_key_pem),
                               derPriv, sizeof(derPriv), NULL);
    if (derPrivSz <= 0)
    {
        printf("Private key PEM to DER failed: %d\n", derPrivSz);
        return derPrivSz;
    }

    // Decode the private key from DER format
    ret = wc_EccPrivateKeyDecode(derPriv, NULL, &myKey, derPrivSz);
    if (ret != 0)
    {
        printf("Private key decode failed: %d\n", ret);
        return ret;
    }

    // Convert public key PEM to DER format
    derPubSz = wc_KeyPemToDer((const byte *)public_key_pem, (word32)strlen(public_key_pem),
                              derPub, sizeof(derPub), NULL);
    if (derPubSz <= 0)
    {
        printf("Public key PEM to DER failed: %d\n", derPubSz);
        return derPubSz;
    }

    // Decode the public key from DER format
    ret = wc_EccPublicKeyDecode(derPub, NULL, &peerKey, derPubSz);
    if (ret != 0)
    {
        printf("Public key decode failed: %d\n", ret);
        return ret;
    }

    // ECDH: Derive shared secret
    ret = wc_ecc_shared_secret(&myKey, &peerKey, shared_secret, &shared_len);
    if (ret != 0)
    {
        printf("ECDH shared secret failed: %d\n", ret);
        return ret;
    }

    // Setup AES using the shared secret and first 16 bytes of the IV
    uint8_t aes_iv[16];
    memcpy(aes_iv, iv_32, 16); // Use first 16 bytes of the 32-byte IV

    ret = wc_AesSetKey(&aes, shared_secret, AES_KEY_SIZE, aes_iv, AES_DECRYPTION);
    if (ret != 0)
    {
        printf("AES set key failed: %d\n", ret);
        return ret;
    }

    // Decrypt the encrypted message (without signature)
    ret = wc_AesCbcDecrypt(&aes, decrypted_output, received_frame, frame_len);
    if (ret != 0)
    {
        printf("AES decryption failed: %d\n", ret);
        return ret;
    }

    // Free ECC keys after use
    wc_ecc_free(&myKey);
    wc_ecc_free(&peerKey);

    return 0;
}



int aes_decrypt(
    const uint8_t *aes_key, 
    const uint8_t *iv_16, 
    const uint8_t *encrypted_data, 
    size_t encrypted_len, 
    uint8_t *decrypted_output)
{
    int ret;
    Aes aes; // AES context

    // Initialize AES context
    ret = wc_AesInit(&aes, NULL, NULL);
    if (ret != 0)
    {
        printf("AES initialization failed: %d\n", ret);
        return ret;
    }

    // Set the AES decryption key using the provided AES key
    ret = wc_AesSetKey(&aes, aes_key, AES_KEY_SIZE, iv_16, AES_DECRYPTION);
    if (ret != 0)
    {
        printf("AES key setup failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }

    // Decrypt the data using AES in CBC mode
    ret = wc_AesCbcDecrypt(&aes, decrypted_output, encrypted_data, encrypted_len);
    if (ret != 0)
    {
        printf("AES decryption failed: %d\n", ret);
        wc_AesFree(&aes);
        return ret;
    }

    // Clean up AES context
    wc_AesFree(&aes);

    return 0; // Decryption successful
}

// #endif // CRYPTO_EXAMPLE
