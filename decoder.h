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

    bool loadDataFromKeyFile();
    bool loadDataFromCiphertextFile();
    bool loadDataFromPlaintextFile();

    bool makeAndWriteDataToCiphertextFile();
    bool makeAndWriteDataToDecipheredTextFile();

    void hex_print(const void* pv, size_t len);
    void hexStringToChar(unsigned char *dataout, std::string datain);

public:
    Decoder(std::ifstream* inputFile, std::ifstream* keyFile, std::fstream* outputFile);

    void encrypt();
    void decrypt();
};

#endif // DECODER_H
