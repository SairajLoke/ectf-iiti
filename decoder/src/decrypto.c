
#include <stdio.h>
#include <stdint.h>
// #include <string.h>

#include "<wolfssl/options.h>"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecdsa.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/aes.h>


#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define AES_BLOCK_SIZE 16


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
    wc_ecc_key myKey, peerKey;
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

int verify_signature(
    unsigned char *message, 
    size_t message_len, 
    unsigned char *signature, 
    size_t signature_len, 
    char *public_key)
{
    int ret;
    byte der[256];

    byte der[256];
    word32 derSize = sizeof(der);
    int ret = wc_KeyPemToDer((const byte *)public_key, strlen(public_key), der, derSize, NULL);
    if (ret < 0)
    {
        printf("PEM to DER failed: %d\n", ret);
        return -1;
    }
    derSize = ret;

    wc_ecc_key pubKey;
    wc_ecc_init(&pubKey);
    ret = wc_EccPublicKeyDecode(der, NULL, &pubKey, derSz);
    if (ret < 0)
    {
        printf("Key decode failed: %d\n", ret);
        return -1;
    }

    // Verify the signature
    int result;
    ret = wc_ecc_verify(signature, signature_len, message, message_len, &result, &ecc_key);

    if (ret < 0)
    {
        printf("Signature verify error: %d\n", ret);
        return -1;
    }

    return result;
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