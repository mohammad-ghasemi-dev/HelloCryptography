#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"

#include <iostream>
#include <string>
#include "HelloCryptography.h"

using namespace CryptoPP;
using namespace std;

auto constexpr PLAINTEXT_FILENAME = "plaintext.jpg";
auto constexpr CIPHERTEXT_FILENAME = "ciphertext.jpg";
auto constexpr RECOVEREDTEXT_FILENAME = "recoveredtext.jpg";
SecByteBlock key(AES::DEFAULT_KEYLENGTH);
SecByteBlock iv(AES::BLOCKSIZE);

int main(int argc, char* argv[])
{
    initialize_key_and_iv();
    encrypt();
    decrypt();
    compare();

    return 0;
}

void initialize_key_and_iv()
{
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
}

void encrypt()
{
    try
    {
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);
        FileSource(PLAINTEXT_FILENAME, true,
            new StreamTransformationFilter(e,
                new FileSink(CIPHERTEXT_FILENAME)
            )
        );
    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}

void decrypt()
{
    try
    {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
        FileSource(CIPHERTEXT_FILENAME, true,
            new StreamTransformationFilter(d,
                new FileSink(RECOVEREDTEXT_FILENAME)
            )
        );
    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}

void compare()
{
    std::string plaintext, recoveredtext;
    try
    {
        FileSource(PLAINTEXT_FILENAME, true, new StringSink(plaintext));
        FileSource(RECOVEREDTEXT_FILENAME, true, new StringSink(recoveredtext));
    }
    catch (const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);

    }

    if (plaintext == recoveredtext)
        cout << "Success: " << PLAINTEXT_FILENAME << " duplicates " << RECOVEREDTEXT_FILENAME << endl;
    else 
        cout << "Failure: " << PLAINTEXT_FILENAME << " and " << RECOVEREDTEXT_FILENAME << " differ" << endl;
}
