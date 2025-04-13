#include <stdio.h>
#include <stdlib.h>
#include <json.h>

#define SECRETS_FILE_PATH "/root/global.secrets"

// Function to read the file contents into a string
char* read_file(const char* filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Unable to open file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = malloc(size + 1);
    if (!content) {
        perror("Unable to allocate memory");
        fclose(file);
        return NULL;
    }

    fread(content, 1, size, file);
    content[size] = '\0';  // Null-terminate the string

    fclose(file);
    return content;
}

// Function to parse the JSON string
void parse_json(const char* json_str) {
    // Parse the JSON string into a JSON object
    struct json_object *parsed_json = json_tokener_parse(json_str);
    if (!parsed_json) {
        fprintf(stderr, "Error parsing JSON\n");
        return;
    }

    // Example of extracting fields from the JSON
    struct json_object *channels, *root_key, *encoder_private_key;
    struct json_object *encoder_public_key, *decoder_private_key;

    if (json_object_object_get_ex(parsed_json, "channels", &channels)) {
        printf("Channels: %s\n", json_object_to_json_string(channels));
    }

    if (json_object_object_get_ex(parsed_json, "root_key", &root_key)) {
        printf("Root Key: %s\n", json_object_to_json_string(root_key));
    }

    if (json_object_object_get_ex(parsed_json, "encoder_private_key", &encoder_private_key)) {
        printf("Encoder Private Key: %s\n", json_object_to_json_string(encoder_private_key));
    }

    if (json_object_object_get_ex(parsed_json, "encoder_public_key", &encoder_public_key)) {
        printf("Encoder Public Key: %s\n", json_object_to_json_string(encoder_public_key));
    }

    if (json_object_object_get_ex(parsed_json, "decoder_private_key", &decoder_private_key)) {
        printf("Decoder Private Key: %s\n", json_object_to_json_string(decoder_private_key));
    }

    // Clean up
    json_object_put(parsed_json);  // Free the memory allocated for the JSON object
}

int old_debug_secrets() {
    // Specify the path to the secrets JSON file
    const char *filename = SECRETS_FILE_PATH;

    // Read the file content
    char *json_str = read_file(filename);
    if (!json_str) {return -1;}

    // Parse the JSON and print values
    parse_json(json_str);

    // Clean up the allocated memory for JSON string
    free(json_str);

}

