
#include <bits/types/FILE.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"



mbedtls_aes_context aes;
mbedtls_aes_context aes2;



#define INPUT_LENGTH 16


unsigned char key[] = {0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
                       0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
                       0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
                       0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
                       0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65};

unsigned char input[INPUT_LENGTH] = {1};

static void cbc()
{
    mbedtls_aes_init(&aes);
    mbedtls_aes_init(&aes2);
    mbedtls_aes_setkey_enc(&aes, key, 256);
    mbedtls_aes_setkey_dec(&aes2, key, 256);

    for(int k=0;k<16;k++){
        input[k]=k;
    }

    unsigned char iv[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char iv1[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char encrypt_output[INPUT_LENGTH] = {0};
    unsigned char decrypt_output[INPUT_LENGTH] = {0};
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, INPUT_LENGTH, iv, input, encrypt_output);
    mbedtls_aes_crypt_cbc(&aes2, MBEDTLS_AES_DECRYPT, INPUT_LENGTH, iv1, encrypt_output, decrypt_output);

    for(int k=0;k<16;k++){
        printf( "%d\n", decrypt_output[k]);
    }


}











int main(void) {
    int ret;


    cbc();




    return ret;
}