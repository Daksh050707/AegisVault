#include<iostream>
#include "pbkdf2.h"
#include<openssl/evp.h>

using namespace std;

void derivekey(const std::string& password, const unsigned char salt[16], unsigned char key[32]) 
{
    const int iterations = 100000;

    int result = PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, 16, iterations, EVP_sha256(), 32, key);

    if(result != 1) 
    {
        std::cout << "Key derivation failed!" << std::endl;
        return;
    }
}
