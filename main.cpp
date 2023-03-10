#include <iostream>
#include <map>
#include <string>
#include <fstream>
#include <iostream>

#include "decoder.h"

enum decoderFunctions {none= -1, encrypt = 1, decrypt = 2};

bool openFile(std::ifstream* file, char* filePath);

int main(int argc, char *argv[])
{
    bool isGenerateNewKey = false;
    decoderFunctions whatToDo = none;
    char* inputFileDirector = NULL;
    char* outputFileDirector = NULL;
    char* keyFileDirector = NULL;

    std::ifstream inputFile;
    std::ifstream keyFile;
    std::fstream outputFile;

    std::map<std::string,int> switchmap
    {
        {"-e", 1},
        {"-d", 2},
        {"-i", 3},
        {"-o", 4},
        {"-k", 5}
    };

    for(int i = 1; i < argc; i++)
    switch(switchmap.find(std::string(argv[i]))->second){
    case 1:
        whatToDo = encrypt;
        break;
    case 2:
        whatToDo = decrypt;
        break;
    case 3:
        i++;
        if(i < argc)  inputFileDirector = argv[i];
        break;
    case 4:
        i++;
        if(i < argc)  outputFileDirector = argv[i];
        break;
    case 5:
        i++;
        if(i < argc)  keyFileDirector = argv[i];
        break;
    }

    bool isCanRun = true;
    isGenerateNewKey = (keyFileDirector == NULL);

    if(inputFileDirector == NULL)
    {
        isCanRun = false;
        printf("Brak sciezki do pliku wejsciowego\n");
    }

    if(outputFileDirector == NULL)
    {
        isCanRun = false;
        printf("Brak sciezki do pliku wyjsciowego\n");
    }

    if(isCanRun)
    {
        printf("Input file = %s\n", inputFileDirector);
        printf("Output file = %s\n", outputFileDirector);
        if(!isGenerateNewKey)
            printf("Key file = %s\n", keyFileDirector);
        printf("\n");

        if(!openFile(&inputFile, inputFileDirector)) return false;
        if(!openFile(&keyFile, keyFileDirector)) return false;

        Decoder decoder(&inputFile, &keyFile, outputFileDirector);

        switch (whatToDo) {
        case encrypt:
            decoder.encrypt();
            break;
        case decrypt:
            decoder.decrypt();
            break;
        default:
            printf("Nieznana operacja.\n");
            return false;
            break;
        }
    }
}

bool openFile(std::ifstream* file, char* filePath)
{
    file->open(filePath);
    if(!file->good())
    {
        printf("Nie mozna otworzyc pliku: %s\n", filePath);
        return false;
    }

    return true;
}
