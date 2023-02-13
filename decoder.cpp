#include "decoder.h"

#include <iostream>
#include <string.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <iomanip>
#include <algorithm>

#include <openssl/evp.h>
#include <openssl/aes.h>

#include "sha256.h"

#define AES_KEYLENGTH 256

Decoder::Decoder(std::ifstream *inputFile, std::ifstream *keyFile, std::string outputPath)
{
    this->inputFile = inputFile;
    this->keyFile = keyFile;
    this->outputPath = outputPath;
}

void Decoder::encrypt()
{
    printf("Start encrypt.\n");
    std::string key; std::string ivData; std::string message;

    loadDataFromPlaintextFile(&message);
    loadDataFromKeyFile(&ivData, &key);

    size_t inputslength = message.length();
    unsigned char aes_input[inputslength];
    unsigned char aes_key[AES_KEYLENGTH];
    memset(aes_input, 0, inputslength/8);
    memset(aes_key, 0, AES_KEYLENGTH/8);

    hexStringToChar(aes_key, key);
    strcpy((char*) aes_input, message.c_str());

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
    AES_set_encrypt_key(aes_key, AES_KEYLENGTH, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv, AES_ENCRYPT);

    printf("original:\t");
    hex_print(aes_input, sizeof(aes_input));
    printf("encrypt:\t");
    hex_print(enc_out, sizeof(enc_out));

    std::string sha, enc_out_string;
    enc_out_string = charToHexString(enc_out, sizeof(enc_out));
    sha = sha256(message);

    if(!makeAndWriteDataToCiphertextFile(outputPath, sha, enc_out_string)) printf("Nie udalo sie zapisac\n");
}

void Decoder::decrypt()
{
    printf("Start decrypt.\n");

    std::string sha, key, ivData, data;

    loadDataFromKeyFile(&ivData, &key);
    loadDataFromCiphertextFile(&sha, &data);

    size_t inputslength = data.length()/2;
    unsigned char aes_input[inputslength];
    unsigned char aes_key[AES_KEYLENGTH];
    memset(aes_input, 0, inputslength/8);
    memset(aes_key, 0, AES_KEYLENGTH/8);

    hexStringToChar(aes_input, data);
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
    AES_set_decrypt_key(aes_key, AES_KEYLENGTH, &dec_key);
    AES_cbc_encrypt(aes_input, dec_out, inputslength, &dec_key, iv, AES_DECRYPT);

    printf("original:\t");
    hex_print(aes_input, sizeof(aes_input));
    printf("decrypt:\t");
    hex_print(dec_out, sizeof(dec_out));

    std::string dec_out_string(reinterpret_cast<char*>(dec_out));
    std::string shaFromString = sha256(dec_out_string);


    if (sha.compare(shaFromString) != 0) {
        printf("Brak zgodnosci.\n");
        return;
    }

    if(!makeAndWriteDataToDecipheredTextFile(outputPath, dec_out_string)) printf("Nie udalo sie zapisac\n");
}

bool Decoder::makeAndWriteDataToDecipheredTextFile(std::string path, std::string data)
{
    std::fstream* file;
    file = new std::fstream(path, std::ios::out);
    if(file->good())
    {
        file->write(data.c_str(), data.length());
        file->flush();
    }
    else
        return false;

    file->close();
    return true;
}

bool Decoder::makeAndWriteDataToCiphertextFile(std::string path, std::string sha, std::string data)
{
    std::fstream* file;
    file = new std::fstream(path, std::ios::out);
    if(file->good())
    {
        std::string nextLine = "\n";
        file->write(sha.c_str(), sha.length());
        file->write(nextLine.c_str(), nextLine.length());
        file->write(data.c_str(), data.length());
        file->flush();
    }
    else
        return false;

    file->close();
    return true;
}

bool Decoder::loadDataFromKeyFile(std::string* iv, std::string* key)
{
    if(!keyFile->eof())
        getline( *keyFile, *iv );
    else
        return false;

    if(!keyFile->eof())
        getline( *keyFile, *key );
    else
        return false;

    keyFile->close();
    return true;
}

bool Decoder::loadDataFromCiphertextFile(std::string* sha, std::string* data)
{
    if(!inputFile->eof())
        getline( *inputFile, *sha );
    else
        return false;

    if(!inputFile->eof())
        getline( *inputFile, *data );
    else
        return false;

    inputFile->close();
    return true;
}

bool Decoder::loadDataFromPlaintextFile(std::string* data)
{
    std::string line;
    while( !inputFile->eof() )
    {
        getline( *inputFile, line );
        *data += line + "\n";
    }

    inputFile->close();
    return true;
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

void Decoder::fromAsciiToString(unsigned char *datain, int length)
{
    for(int i = 0; i < length; i++)
        printf("%c", datain[i]);
    printf("\n");
}

std::string Decoder::charToHexString(const void* pv, size_t len)
{
    std::stringstream stream;
}
