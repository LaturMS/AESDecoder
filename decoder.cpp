#include "decoder.h"

#include <iostream>
#include <string.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/aes.h>

#define AES_KEYLENGTH 256

Decoder::Decoder(std::ifstream *inputFile, std::ifstream *keyFile, std::fstream *outputFile)
{
    this->inputFile = inputFile;
    this->keyFile = keyFile;
    this->outputFile = outputFile;
}

void Decoder::encrypt()
{
    printf("Start encrypt.\n");
    std::string key; std::string ivData; std::string message;

    size_t inputslength = message.length();
    unsigned char aes_input[inputslength];
    unsigned char aes_key[AES_KEYLENGTH];
    memset(aes_input, 0, inputslength/8);
    memset(aes_key, 0, AES_KEYLENGTH/8);

//    stringToHexChar(message, aes_input);
    hexStringToChar(aes_key, key);

    strcpy((char*) aes_input, message.c_str());
//    strcpy((char*) aes_key, key.c_str());

    /* init vector */
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);
    hexStringToChar(iv, ivData);

    // buffers for encryption and decryption
    const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[encslength];
    unsigned char dec_out[inputslength];
    memset(enc_out, 0, sizeof(enc_out));
    memset(dec_out, 0, sizeof(dec_out));

    AES_KEY enc_key;
//    AES_set_encrypt_key(aes_key, AES_KEYLENGTH, &enc_key);
//    AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv, AES_ENCRYPT);

    printf("original:\t");
    hex_print(aes_input, sizeof(aes_input));
    printf("encrypt:\t");
    hex_print(enc_out, sizeof(enc_out));

//    fromAsciiToString(dec_out, sizeof(enc_out));

    std::stringstream ss;
    for(int i = 0; i < encslength; i++)
    {
        ss << enc_out[i];
    }
}

void Decoder::decrypt()
{
    printf("Start decrypt.\n");

    std::string key; std::string ivData; std::string message;

    size_t inputslength = message.length()/2;
    unsigned char aes_input[inputslength];
    unsigned char aes_key[AES_KEYLENGTH];
    memset(aes_input, 0, inputslength/8);
    memset(aes_key, 0, AES_KEYLENGTH/8);

    hexStringToChar(aes_input, message);
    hexStringToChar(aes_key, key);

    /* init vector */
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);
    hexStringToChar(iv, ivData);

    // buffers for encryption and decryption
    unsigned char enc_out[inputslength];
    unsigned char dec_out[inputslength];
    memset(enc_out, 0, sizeof(enc_out));
    memset(dec_out, 0, sizeof(dec_out));

    AES_KEY dec_key;
//    AES_set_decrypt_key(aes_key, AES_KEYLENGTH, &dec_key);
//    AES_cbc_encrypt(aes_input, dec_out, inputslength, &dec_key, iv, AES_DECRYPT);

    printf("original:\t");
    hex_print(aes_input, sizeof(aes_input));
    printf("decrypt:\t");
    hex_print(dec_out, sizeof(dec_out));

//    fromAsciiToString(dec_out, sizeof(enc_out));

    std::stringstream ss;
    for(int i = 0; i < inputslength; i++)
    {
        ss << enc_out[i];
    }
}

// a simple hex-print routine. could be modified to print 16 bytes-per-line
void Decoder::hex_print(const void* pv, size_t len)
{
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i<len;++i)
        {
//            if(i % 16 == 0) printf(" | ");
            printf("%02X", *p++);
        }
    }
    printf("\n");
}

void Decoder::hexStringToChar(unsigned char *dataout, std::string datain)
{
    std::string newString;
    for(int i=0, j=0; i< datain.length(); i+=2, j++)
    {
        std::string byte = datain.substr(i,2);
        char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
        dataout[j] = chr;
    }
}
