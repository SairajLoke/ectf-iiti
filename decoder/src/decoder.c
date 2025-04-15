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

// #include "<wolfssl/options.h>"
// #include <wolfssl/ssl.h>
// #include <wolfssl/wolfcrypt/ecdsa.h>
// #include <wolfssl/wolfcrypt/hash.h>

#include "simple_uart.h"

/* Code between this #ifdef and the subsequent #endif will
 *  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
 *  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
// OUR Security realted files using wolfSSL
// #include "security_utils.h" can do this but printing becomes an issue...so rather inlcude secrets.h here
#include "secrets.h"
#include "simple_crypto.h"
#include "decrypto.h"
/* The simple crypto example included with the reference design is intended
 *  to be an example of how you *may* use cryptography in your design. You
 *  are not limited nor required to use this interface in your design. It is
 *  recommended for newer teams to start by only using the simple crypto
 *  library until they have a working design. */

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
    for (int i = 0; i < (NUM_CHANNELS_EXCEPT_0 + 1); ++i)
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

    // print_debug("Channel 0 Key:");
    // print_key(CHANNEL_0_KEY, 32);

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


#endif // CRYPTO_EXAMPLE

/******************* PRIMITIVE TYPES **********************/
#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/*********************** CONSTANTS ************************/
#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

/********************* STATE MACROS ***********************/
// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

/*********** COMMUNICATION PACKET DEFINITIONS *************/
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

/******************** TYPE DEFINITIONS ********************/
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

/************************ GLOBALS *************************/
// This is used to track decoder subscriptions
flash_entry_t decoder_status;
uint8_t encrypted_buf[256]; // Adjust size as needed
uint8_t decrypted_buf[256];
pkt_len_t pkt_len;



/******************* UTILITY FUNCTIONS ********************/
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


/********************* CORE FUNCTIONS *********************/
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



/************************** SUBSCRIPTION FUNCTION *****************/
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
    //printfew starting bytes 
    print_debug("Updating subscription...\n");
    // print_debug(
    // Check that the packet is the correct size
    // if (pkt_len != sizeof(subscription_update_packet_t))
    // {
    //     STATUS_LED_RED();
    //     print_error("Invalid packet size\n"); need to check this
    //     return -1;
    // }
    //verify the signature of the update packet
    // if (verify_signature(update->data, pkt_len, update->signature, sizeof(update->signature), SIGNATURE_PUBLIC_KEY) != 0)
    // {   
    //     STATUS_LED_RED();
    //     print_error("Failed to verify signature\n");
    //     return -1;
    // }


    // Check that the channel is valid
    if (update->channel > MAX_CHANNEL_COUNT)
    {
        STATUS_LED_RED();
        print_error("Invalid channel number\n");
        return -1;
    }

    // Check that the start and end timestamps are valid
    if (update->start_timestamp > update->end_timestamp)
    {
        STATUS_LED_RED();
        print_error("Invalid timestamp range\n");
        return -1;
    }


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
        if (decoder_status.subscribed_channels[i].id == update->channel || 
            !decoder_status.subscribed_channels[i].active)
        {
            decoder_status.subscribed_channels[i].active = true; //keys are always there...but decrypted only if this is true and timestamps are in valid range 
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


/* Helper function to handle PKCS7 padding removal */
void remove_padding(uint8_t *data, int *len) {
    int padding_len = data[*len - 1];
    *len -= padding_len; // Adjust the length
}

void int2str(int num, char *str) {
    int i = 0;
    char pkt_len_buf [64];
    while (num != 0) {
        str[i++] = (num % 10) + '0';
        num /= 10;
    }
    str[i] = '\0';
    // Reverse the string
    for (int j = 0; j < i / 2; j++) {
        char temp = str[j];
        str[j] = str[i - j - 1];
        str[i - j - 1] = temp;
    }
    print_debug(pkt_len_buf);
}

void print_subscription_packet(const subscription_update_packet_t *packet) {
    char buf[128];
    snprintf(buf, sizeof(buf),
             "Subscription Packet:\n"
             "  Decoder ID : %u\n"
             "  Channel    : %u\n"
             "  Start Time : %llu\n"
             "  End Time   : %llu\n",
             packet->decoder_id,
             packet->channel,
             (unsigned long long)packet->start_timestamp,
             (unsigned long long)packet->end_timestamp);
    print_debug(buf);
}

int handle_update_subscription(size_t pkt_len, uint8_t *uart_buf) {
    
    int2str(pkt_len);
    // if( pkt_len == 80){print_debug("Yes, 80 bytes");}
    // else if (pkt_len < 80){print_debug("No, less than 80 bytes");}
    // else if (pkt_len > 80){print_debug("No, more than 80 bytes");}
    // else {print_debug("No, invalid length");}

    print_debug("pkt len: - should be 48bytes = 16iv + 32data[24 IQQI + 8padding]");
    
    // print_hex_debug(pkt_len_buf, pkt_len);
    // print_hex_debug(&pkt_len, sizeof(pkt_len));

    // // Extract the signature and the encrypted message
    // uint8_t *signature = uart_buf;
    // uint8_t *encrypted_message = uart_buf + SIGNATURE_LENGTH;
    // size_t encrypted_message_len = pkt_len - SIGNATURE_LENGTH;
    //signature verification , there is no signature in subscription update packet
    // int result = verify_signature(encrypted_message, encrypted_message_len, signature, SIGNATURE_LENGTH);
    // if (result != 0) {
    //     print_debug("Failed to verify signature\n");
    //     return -1;
    // }
    print_debug("Ufff no subscription Signature verification\n");

    // Extract the IV (first 16 bytes)
    uint8_t iv[AES_BLOCK_SIZE];
    memcpy(iv, uart_buf, AES_BLOCK_SIZE);

    

    // Initialize the AES decryption context with the subscription key
    Aes aes;
    if (wc_AesInit(&aes, NULL, 0) != 0) {
        print_debug("AES initialization failed\n");
        return -1;
    }

    /* Set the AES key.
       Note: Our SUBSCRIPTION_KEY is 32 bytes, so we're using AES-256.
       Use WC_AES_DECRYPT as the direction flag.
    */
    if (wc_AesSetKey(&aes, SUBSCRIPTION_KEY, 32, iv, AES_DECRYPTION) != 0) {//wc_AesSetKey(&aes, key, key_len, iv, AES_DECRYPTION);
        print_debug("Setting AES key failed\n");
        return -1;
    }

    int encrypted_data_len = (int)pkt_len - AES_BLOCK_SIZE;
    // Decrypt the packet (after the IV, i.e., uart_buf + AES_BLOCK_SIZE)
    uint8_t decrypted_data[encrypted_data_len]; // MAX_SUBSCRIPTION_PACKET_SIZE : 48bytes = 16iv + 32data[24 IQQI + 8padding]
    int decrypted_len = 0;

    if (wc_AesCbcDecrypt(&aes, decrypted_data, uart_buf + AES_BLOCK_SIZE, encrypted_data_len) != 0) { //WOLFSSL_API int  wc_AesCbcDecrypt(Aes* aes, byte* out , const byte* in, word32 sz);
        print_debug("AES decryption failed\n");
        return -1;
    }  

    // Remove PKCS7 padding
    remove_padding(decrypted_data, &decrypted_len);

    // Ensure we have a valid subscription packet
    if (decrypted_len != sizeof(subscription_update_packet_t)) {
        print_error("Invalid decrypted length\n");
        
        return -1;  // Invalid length after decryption
    }

    // Parse the decrypted data into the subscription_update_packet_t structure
    subscription_update_packet_t packet;
    memcpy(&packet, decrypted_data, sizeof(subscription_update_packet_t));

    // // Now extract the information from the decrypted frame (assumes struct frame_packet_t exists)
    subscription_update_packet_t *sub_packet = &packet;
    channel_id_t channel = sub_packet->channel;
    timestamp_t start = sub_packet->start_timestamp;
    timestamp_t end = sub_packet->end_timestamp;
    decoder_id_t id = sub_packet->decoder_id;

    print_subscription_packet(sub_packet);
    // Print the extracted information
    // print_hex_debug(channel, sizeof(channel));

    // print_debug("Channel: " + str(channel) + "start: " + str(start) + "end: " + str(end) + "DecoderID: " + str(id) + "\n");

    // update_subscription(sizeof(subscription_update_packet_t), sub_packet);//to check
    // // If everything is valid, process the decrypted frame
    // write_packet(SUBSCRIBE_MSG, NULL, 0); // Send an ACK message

    return 0;
}



int perform_checks(channel_id_t channel, timestamp_t timestamp){
    // checking all the channel conditions and timestamp conditions before decrypting the frame.
    if (channel > MAX_CHANNEL_COUNT)
    {
        STATUS_LED_RED();
        print_error("Invalid channel number\n");
        return -1;
    }
    if(is_subscribed(channel) != 1)
    {
        STATUS_LED_RED();
        print_error("Not subscribed to channel\n");
        return -1;
    }
    if (timestamp < decoder_status.subscribed_channels[channel].start_timestamp || timestamp > decoder_status.subscribed_channels[channel].end_timestamp)
    {
        STATUS_LED_RED();
        print_error("Invalid timestamp range\n");
        return -1;
    }

    print_debug("Subscription Valid\n");
    print_debug("Valid timestamp range\n");
    return 0;
}



/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len  The length of the incoming packet
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful.  -1 if data is from unsubscribed channel.
 */
// packet[message[frame,channel,timestamp], signature]
int decode(pkt_len_t pkt_len, frame_packet_t *new_frame_packet)
{ return 0;
//     // Check that the packet is the correct size
//     // if (pkt_len != (sizeof(frame_packet_t) + SIGNATURE_LENGTH))
//     // {
//     //     STATUS_LED_RED();
//     //     print_error("Invalid packet size\n");
//     //     return -1;
//     // }

//     // char output_buf[128] = {0}; whyyy
//     uint16_t frame_size;
//     channel_id_t channel;
//     print_debug("Decrypting...\n"); 

//     // Signature and message extraction from new frame
//     // size_t signature_len = 64; // 64 bytes for ECDSA signature (32 bytes for r and 32 bytes for s)
//     size_t message_len = pkt_len - SIGNATURE_LENGTH ; //ig not .....sizeof(new_frame) - signature_len;
//     uint8_t *signature = new_frame_packet;                         // Points to first 64 bytes
//     //TODO check the ptr arithmetic here
//     uint8_t *encrypted_message = new_frame_packet + SIGNATURE_LENGTH ; // Points to the encrypted message part
//     uint8_t frame_size = message_len-(sizeof(new_frame->channel) + sizeof(new_frame->timestamp));

//     int result = verify_signature(encrypted_message, message_len, signature, signature_len, SIGNATURE_PUBLIC_KEY) ;
//     if (result != 0){
//         STATUS_LED_RED();
//         print_error("FAILED to VERIFY SIGNATURE\n");
//         return -1;

//     }
    
//     // Perform ECDH Decryption to obtain the packet, // perform ecdsa decryption using the private key of decoder on the packet
//     uint8_t received_frame[256];
//     uint8_t iv_32[32]; //should be 16
//     frame_packet_t *decrypted_frame[192];
//     if(ecdh_decrypt(DECODER_PRIVATE_KEY, ENCODER_PUBLIC_KEY, iv_32, received_frame, sizeof(received_frame), decrypted) != 0) //returns non-zero on failure //can be checked if(condition)...but doint explicity != 0 readability
//     {
//         STATUS_LED_RED();
//         print_error("Failed to decrypt frame data\n");
//         return -1;
//     }

//     // extract time frame and channel and encrypted frame
//     channel_id_t channel = decrypted_frame->channel;
//     timestamp_t timestamp = decrypted_frame->timestamp;
//     uint8_t frame_data[FRAME_SIZE] = decrypted_frame->frame;
//     perform_checks(channel, timestamp);


//     // Decrypt the frame data using the channel key
//     // channel_key = channel_keys[channel]; read from header file
//     // if(decrypt_sym(frame_data, FRAME_SIZE, channel_key, decrypted_frame) != 0)
//     // frame_packet_t *decrypted_frame = (frame_packet_t *)decrypted_buf;
//     ////to do this+++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//     // if(decrypt_sym(new_frame_packet->data, 
//     //                pkt_len - (sizeof(new_frame_packet->channel) + sizeof(new_frame_packet->timestamp)), 
//     //                (uint8_t *)decrypted_frame, 
//     //                (uint8_t *)DECODER_PRIVATE_KEY) != 0)
//     // {
//     //     STATUS_LED_RED();
//     //     print_error("Failed to decrypt frame data\n");
//     //     return -1;
//     // }
//     //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

//     //check decrypted frame
//     if(decrypted_frame->channel != channel)
//     {
//         STATUS_LED_RED();
//         print_error("Decrypted frame channel does not match\n");
//         return -1;
//     }
//     if(decrypted_frame->timestamp != timestamp)
//     {
//         STATUS_LED_RED();
//         print_error("Decrypted frame timestamp does not match\n");
//         return -1;
//     }

//     // Frame size is the size of the packet minus the size of non-frame elements
//     write_packet(DECODE_MSG, decrypted_frame->frame, frame_size);
//     return 0;

}

int old_decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};
    uint16_t frame_size;
    channel_id_t channel;

    // Frame size is the size of the packet minus the size of non-frame elements
    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp));
    channel = new_frame->channel;

    // The reference design doesn't use the timestamp, but you may want to in your design
    // timestamp_t timestamp = new_frame->timestamp;

    // Check that we are subscribed to the channel...
    print_debug("Checking subscription\n");
    if (is_subscribed(channel)) {
        print_debug("Subscription Valid\n");
        /* The reference design doesn't need any extra work to decode, but your design likely will.
        *  Do any extra decoding here before returning the result to the host. */
        write_packet(DECODE_MSG, new_frame->data, frame_size);
        return 0;
    } else {
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




// void debug_uart(uint16_t pkt_len, const uint8_t *uart_buf, char *ascii_output, size_t ascii_len) {
//     for (int i = 0; i < ascii_len-1 && i < pkt_len; ++i) {
//         ascii_output[i] = (uart_buf[i] >= 32 && uart_buf[i] <= 126) ? uart_buf[i] : '.'; // Printable ASCII or '.'
//     }
//     ascii_output[ascii_len-1] = '\0'; // Null-terminate the string
//     print_hex_debug(ascii_output, ascii_len); // Print the ASCII representation
    // ufff
// }
// #define UART_DEBUG_LEN 10

/*********************** MAIN LOOP ************************/
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
        // debug_uart(pkt_len, uart_buf, ascii_output, UART_DEBUG_LEN);
        print_hex_debug(uart_buf, pkt_len); // Print the hex representation
        
        // read few bytes from the buffer and convert to ascii before sending to debug
        print_debug("||||||||||||||  Received UART buffer |||||||||");


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
            crypto_example();
            // TODO: Remove this from your design
            debug_secrets();
            #endif // CRYPTO_EXAMPLE

            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            old_decode(pkt_len, (frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            handle_update_subscription(pkt_len, uart_buf);
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
