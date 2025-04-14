/**
 * @file    decoder.c
 * @author  Samuel Meyers
 * @brief   eCTF Decoder Example Design Implementation
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "<wolfssl/options.h>"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecdsa.h>
#include <wolfssl/wolfcrypt/hash.h>

#include "simple_uart.h"

/* Code between this #ifdef and the subsequent #endif will
 *  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
 *  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE

// OUR Security realted files using wolfSSL
// #include "security_utils.h" can do this but printing becomes an issue...so rather inlcude secrets.h here
#include "secrets.h"

void print_key(const uint8_t *key, size_t length)
{
    // Max 3 chars per byte (e.g., "ff:"), plus one for '\0'
    char buffer[32 * 3 + 1];
    size_t offset = 0;

    for (size_t i = 0; i < length; ++i)
    {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                           (i < length - 1) ? "%02x:" : "%02x", key[i]);
        if (offset >= sizeof(buffer) - 1)
            break; // Avoid buffer overrun
    }

    buffer[offset] = '\0'; // Just in case
    print_debug(buffer);
}

int debug_secrets()
{

    print_debug("$$$$$$$$$$$$$$$$$$$$$$$$ Valid Channels: ");
    for (int i = 0; i < NUM_CHANNELS; ++i)
    {
        char buf[8];
        snprintf(buf, sizeof(buf), "%d ", VALID_CHANNELS[i]);
        print_debug(buf);
    }
    print_debug("\n");

    print_debug("Root Key:");
    print_key(ROOT_KEY, 32);

    print_debug("Subscription Key:");
    print_key(SUBSCRIPTION_KEY, 32);

    print_debug("Channel 0 Key:");
    print_key(CHANNEL_0_KEY, 32);

    print_debug("Channel 1 Key:");
    print_key(CHANNEL_1_KEY, 32);

    print_debug("Channel 3 Key:");
    print_key(CHANNEL_3_KEY, 32);

    print_debug("Channel 4 Key:");
    print_key(CHANNEL_4_KEY, 32);

    print_debug("Encoder Public Key:");
    print_debug(ENCODER_PUBLIC_KEY);

    print_debug("Decoder Private Key:");
    print_debug(DECODER_PRIVATE_KEY);

    print_debug("Signature Public Key:");
    print_debug(SIGNATURE_PUBLIC_KEY);

    return 0;
}

/* The simple crypto example included with the reference design is intended
 *  to be an example of how you *may* use cryptography in your design. You
 *  are not limited nor required to use this interface in your design. It is
 *  recommended for newer teams to start by only using the simple crypto
 *  library until they have a working design. */
#include "simple_crypto.h"
#endif // CRYPTO_EXAMPLE

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html
typedef struct
{
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t data[FRAME_SIZE];
} frame_packet_t;

typedef struct
{
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
} subscription_update_packet_t;

typedef struct
{
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct
{
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

typedef struct
{
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct
{
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;
uint8_t encrypted_buf[256]; // Adjust size as needed
uint8_t decrypted_buf[256];
pkt_len_t pkt_len;

/**********************************************************
 ******************** REFERENCE FLAG **********************
 **********************************************************/

// trust me, it's easier to get the boot reference flag by
// getting this running than to try to untangle this
// TODO: remove this from your final design
// NOTE: you're not allowed to do this in your code
typedef uint32_t aErjfkdfru;
const aErjfkdfru aseiFuengleR[] = {0x1ffe4b6, 0x3098ac, 0x2f56101, 0x11a38bb, 0x485124, 0x11644a7, 0x3c74e8, 0x3c74e8, 0x2f56101, 0x2ca498, 0x127bc, 0x2e590b1, 0x1d467da, 0x1fbf0a2, 0x11a38bb, 0x2b22bad, 0x2e590b1, 0x1ffe4b6, 0x2b61fc1, 0x1fbf0a2, 0x1fbf0a2, 0x2e590b1, 0x11644a7, 0x2e590b1, 0x1cc7fb2, 0x1d073c6, 0x2179d2e, 0};
const aErjfkdfru djFIehjkklIH[] = {0x138e798, 0x2cdbb14, 0x1f9f376, 0x23bcfda, 0x1d90544, 0x1cad2d2, 0x860e2c, 0x860e2c, 0x1f9f376, 0x25cbe0c, 0x11c82b4, 0x35ff56, 0x3935040, 0xc7ea90, 0x23bcfda, 0x1ae6dee, 0x35ff56, 0x138e798, 0x21f6af6, 0xc7ea90, 0xc7ea90, 0x35ff56, 0x1cad2d2, 0x35ff56, 0x2b15630, 0x3225338, 0x4431c8, 0};
typedef int skerufjp;
skerufjp siNfidpL(skerufjp verLKUDSfj)
{
    aErjfkdfru ubkerpYBd = 12 + 1;
    skerufjp xUrenrkldxpxx = 2253667944 % 0x432a1f32;
    aErjfkdfru UfejrlcpD = 1361423303;
    verLKUDSfj = (verLKUDSfj + 0x12345678) % 60466176;
    while (xUrenrkldxpxx-- != 0)
    {
        verLKUDSfj = (ubkerpYBd * verLKUDSfj + UfejrlcpD) % 0x39aa400;
    }
    return verLKUDSfj;
}
typedef uint8_t kkjerfI;
kkjerfI deobfuscate(aErjfkdfru veruioPjfke, aErjfkdfru veruioPjfwe)
{
    skerufjp fjekovERf = 2253667944 % 0x432a1f32;
    aErjfkdfru veruicPjfwe, verulcPjfwe;
    while (fjekovERf-- != 0)
    {
        veruioPjfwe = (veruioPjfwe - siNfidpL(veruioPjfke)) % 0x39aa400;
        veruioPjfke = (veruioPjfke - siNfidpL(veruioPjfwe)) % 60466176;
    }
    veruicPjfwe = (veruioPjfke + 0x39aa400) % 60466176;
    verulcPjfwe = (veruioPjfwe + 60466176) % 0x39aa400;
    return veruicPjfwe * 60466176 + verulcPjfwe - 89;
}

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
 */
int is_subscribed(channel_id_t channel)
{
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL)
    {
        return 1;
    }
    // Check if the decoder has has a subscription
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++)
    {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active)
        {
            return 1;
        }
    }
    return 0;
}

/** @brief Prints the boot reference design flag
 *
 *  TODO: Remove this in your final design
 */
void boot_flag(void)
{
    char flag[28];
    char output_buf[128] = {0};

    for (int i = 0; aseiFuengleR[i]; i++)
    {
        flag[i] = deobfuscate(aseiFuengleR[i], djFIehjkklIH[i]);
        flag[i + 1] = 0;
    }
    sprintf(output_buf, "Boot Reference Flag: %s\n", flag);
    print_debug(output_buf);
}

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
 */
int list_channels()
{
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;

    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++)
    {
        if (decoder_status.subscribed_channels[i].active)
        {
            resp.channel_info[resp.n_channels].channel = decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // Success message
    write_packet(LIST_MSG, &resp, len);
    return 0;
}

/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param pkt_len The length of the incoming packet
 *  @param update A pointer to an array of channel_update structs,
 *      which contains the channel number, start, and end timestamps
 *      for each channel being updated.
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success.  -1 if error.
 */

int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update)
{
    int i;

    if (update->channel == EMERGENCY_CHANNEL)
    {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }

    // Find the first empty slot in the subscription array
    for (i = 0; i < MAX_CHANNEL_COUNT; i++)
    {
        if (decoder_status.subscribed_channels[i].id == update->channel || !decoder_status.subscribed_channels[i].active)
        {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = update->channel;
            decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
            break;
        }
    }

    // If we do not have any room for more subscriptions
    if (i == MAX_CHANNEL_COUNT)
    {
        STATUS_LED_RED();
        print_error("Failed to update subscription - max subscriptions installed\n");
        return -1;
    }

    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    // Success message with an empty body
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

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

int verify_signature(unsigned char *message, size_t message_len, unsigned char *signature, size_t signature_len, char *public_key)
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

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_IV_SIZE 16

int aes_decrypt(const uint8_t *aes_key, const uint8_t *iv_16, const uint8_t *encrypted_data, size_t encrypted_len, uint8_t *decrypted_output)
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

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful.  -1 if data is from unsubscribed channel.
 */

int decode(pkt_len_t pkt_len, frame_packet_t *new_frame)
{
    char output_buf[128] = {0};
    uint16_t frame_size;
    channel_id_t channel;

    // perform ecdsa decryption using the private key of decoder on the packet
    print_debug("Decrypting...\n");

    // Signature and message extraction from new frame
    size_t signature_len = 64;
    size_t message_len = sizeof(new_frame) - signature_len;
    uint8_t *signature = new_frame;                         // Points to first 64 bytes
    uint8_t *encrypted_message = new_frame + signature_len; // Points to the rest

    int result = verify_signature(encrypted_message, message_len, signature, signature_len, SIGNATURE_PUBLIC_KEY) if (result)
    {
        // Perform ECDH Decryption to obtain the packet
        uint8_t received_frame[256];
        uint8_t iv_32[32];
        frame_packet_t *decrypted_frame[192];
        ecdh_decrypt(DECODER_PRIVATE_KEY, ENCODER_PUBLIC_KEY, iv_32, received_frame, sizeof(received_frame), decrypted);

        // extract time frame and channel and encrypted frame
        channel_id_t channel = decrypted_frame->channel;
        timestamp_t timestamp = decrypted_frame->timestamp;
        uint8_t data[FRAME_SIZE] = decrypted_frame->frame;

        // checking all the channel conditions and timestamp conditions before decrypting the frame.
        // define channel_keys = {}
        channel_key = channel_keys[channel];
    }

    // frame_packet_t *decrypted_frame = (frame_packet_t *)decrypted_buf;
    int ret = decrypt_sym(new_frame->data, pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp)), (uint8_t *)decrypted_frame, (uint8_t *)DECODER_PRIVATE_KEY);
    if (ret < 0)
    {
        STATUS_LED_RED();
        print_error("Failed to decrypt frame data\n");
        return -1;
    }
    // Check that the decrypted frame is valid

    // Frame size is the size of the packet minus the size of non-frame elements
    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp));
    channel = new_frame->channel;

    // The reference design doesn't use the timestamp, but you may want to in your design
    // timestamp_t timestamp = new_frame->timestamp;

    // Check that we are subscribed to the channel...
    print_debug("Checking subscription\n");
    if (is_subscribed(channel))
    {
        print_debug("Subscription Valid\n");
        /* The reference design doesn't need any extra work to decode, but your design likely will.
         *  Do any extra decoding here before returning the result to the host. */
        write_packet(DECODE_MSG, new_frame->data, frame_size);
        return 0;
    }
    else
    {
        STATUS_LED_RED();
        sprintf(
            output_buf,
            "Receiving unsubscribed channel data.  %u\n", channel);
        print_error(output_buf);
        return -1;
    }
}

/** @brief Initializes peripherals for system boot.
 */
void init()
{
    int ret;

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT)
    {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
         *  This data will be persistent across reboots of the decoder. Whenever the decoder
         *  processes a subscription update, this data will be updated.
         */
        print_debug("First boot.  Setting flash...\n");

        decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++)
        {
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT * sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0)
    {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1)
            ;
    }
}

/* Code between this #ifdef and the subsequent #endif will
 *  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
 *  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
void crypto_example(void)
{
    // Example of how to utilize included simple_crypto.h

    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    char *data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t key[KEY_SIZE];
    uint8_t hash_out[HASH_SIZE];
    uint8_t decrypted[BLOCK_SIZE];

    char output_buf[128] = {0};

    // Zero out the key
    bzero(key, BLOCK_SIZE);

    // Encrypt example data and print out
    encrypt_sym((uint8_t *)data, BLOCK_SIZE, key, ciphertext);
    print_debug("Encrypted data: \n");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Hash example encryption results
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: \n");
    print_hex_debug(hash_out, HASH_SIZE);

    // Decrypt the encrypted message and print out
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    sprintf(output_buf, "Decrypted message: %s\n", decrypted);
    print_debug(output_buf);
}
#endif // CRYPTO_EXAMPLE

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void)
{
    char output_buf[128] = {0};
    uint8_t uart_buf[100];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    print_debug("Decoder Booted!\n");

    // process commands forever
    while (1)
    {
        print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0)
        {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch (cmd)
        {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();

#ifdef CRYPTO_EXAMPLE
            // Run the crypto example
            // TODO: Remove this from your design
            debug_secrets();
            crypto_example();

            // if (debug_secrets()==-1){
            //     STATUS_LED_ERROR();
            //     print_error("Failed to read secrets\n");
            // }
#endif // CRYPTO_EXAMPLE

            // Print the boot flag
            // TODO: Remove this from your design
            boot_flag();
            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_ERROR();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
