#ifndef DECODER_H
#define DECODER_H

#include <fstream>
#include <iostream>

class Decoder
{
private:
    std::ifstream* inputFile;
    std::ifstream* keyFile;
    std::fstream* outputFile;

    bool makeAndWriteDataToDecipheredTextFile(std::string path, std::string data);
    bool makeAndWriteDataToCiphertextFile(std::string path, std::string sha, std::string data);

    bool loadDataFromKeyFile(std::string* iv, std::string* key);
    bool loadDataFromCiphertextFile(std::string* sha, std::string* data);
    bool loadDataFromPlaintextFile(std::string *data);

    bool makeAndWriteDataToCiphertextFile();
    bool makeAndWriteDataToDecipheredTextFile();

    void hex_print(const void* pv, size_t len);
    void hexStringToChar(unsigned char *dataout, std::string datain);
    void fromAsciiToString(unsigned char *datain, int length);

    std::string charToHexString(const void *pv, size_t len);
public:
    Decoder(std::ifstream* inputFile, std::ifstream* keyFile, std::fstream* outputFile);

    void encrypt();
    void decrypt();
};

#endif // DECODER_H
