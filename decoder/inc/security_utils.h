#include <stdio.h>

#include "secrets.h"

void print_key(const uint8_t *key, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", key[i]);
        if (i < length - 1) printf(":");
    }
    printf("\n");
}

int debug_secrets() {

    //do a check on file path exists else return -1

    // Read the file content
    // FILE *file = fopen(SECRETS_FILE_PATH, "r");
    // if (!file) {
    //     perror("Failed to open secrets file");
    //     return -1;
    // }


    printf("Valid Channels: ");
    for (int i = 0; i < NUM_CHANNELS; ++i) {
        printf("%d ", VALID_CHANNELS[i]);
    }
    printf("\n\n");

    printf("Root Key:\n");
    print_key(ROOT_KEY, 32);

    printf("Subscription Key:\n");
    print_key(SUBSCRIPTION_KEY, 32);

    printf("Channel 0 Key:\n");
    print_key(CHANNEL_0_KEY, 32);

    printf("\nEncoder Public Key:\n%s\n", ENCODER_PUBLIC_KEY);
    printf("Decoder Private Key:\n%s\n", DECODER_PRIVATE_KEY);
    printf("Signature Public Key:\n%s\n", SIGNATURE_PUBLIC_KEY);

    return 0;
}
