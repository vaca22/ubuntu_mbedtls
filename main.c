
#include <bits/types/FILE.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/sha256.h"


#define BUFFER_SIZE 4096
#define HASH_SIZE 32



int main(void) {
    int ret;

    // Initialize hash
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, /*is224=*/0);

    // Open file
    FILE *fp = fopen("/home/vaca/esp32YUlin/mbedtls_test/fuck", "r");
    if (fp == NULL) {
        ret = EXIT_FAILURE;
        goto exit;
    }

    // Read file in chunks of size BUFFER_SIZE
    uint8_t buffer[BUFFER_SIZE];
    size_t read;
    while ((read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
        mbedtls_sha256_update_ret(&ctx, buffer, read);
    }

    // Calculate final hash sum
    uint8_t hash[HASH_SIZE];
    mbedtls_sha256_finish_ret(&ctx, hash);

    // Simple debug printing. Use MBEDTLS_SSL_DEBUG_BUF in a real program.
    for (size_t i = 0; i < HASH_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    // Cleanup
    fclose(fp);
    ret = EXIT_SUCCESS;

    exit:
    mbedtls_sha256_free(&ctx);
    return ret;
}