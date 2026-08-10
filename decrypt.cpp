#include<iostream>
#include"decrypt.h"
#include<fstream>
#include<openssl/evp.h>
#include<cstring>
#include<vector>
#include "crypto.h"
#include"pbkdf2.h"

const char FILE_HEADER[] = "AEGISVAULT";
const unsigned char VERSION = 2;

using namespace std;

void decryptFile()
{
    cout<<"---------------------------------------------------------------"<<endl;
    cout<<"                  DECRYPTION MODULE STARTED!                   "<<endl;
    cout<<"---------------------------------------------------------------"<<endl;

    cout<<endl;

    cout<<"Decrypting file..."<<endl;

    string password;

    unsigned char key[32];
    unsigned char salt[16];
    unsigned char iv[16];

    char header[sizeof(FILE_HEADER)];
    unsigned char version;

    unsigned char extensionLength;
    string extension;

    cout << "Enter password : ";
    cin >> password;

    int ciphertext_len = 0;

    ifstream inputFile("Output/encrypted.aegis", ios::binary);
    if (!inputFile)
    {
        cout << "Encrypted file not found in the Output folder!" << endl;
        return;
    }

    inputFile.read(header, sizeof(FILE_HEADER));
    inputFile.read((char*)&version, sizeof(version));

    inputFile.read((char*)&extensionLength, sizeof(extensionLength));

    char extensionBuffer[20];

    inputFile.read(extensionBuffer, extensionLength);

    extension.assign(extensionBuffer, extensionLength);

    if (strcmp(header, FILE_HEADER) != 0)
    {
        cout<<endl;
        cout << "---------------------------------------------"<<endl;
        cout << "                INVALID FILE"<<endl;
        cout << "---------------------------------------------"<<endl;
        cout<<"This is not an AegisVault encrypted file."<<endl;
        cout<<"Decryption aborted."<<endl;
        return;
    }
    if (version != VERSION)
    {
        cout << "Unsupported AegisVault file version!" << endl;
        return;
    }

    inputFile.read((char*)salt, 16);
    inputFile.read((char*)iv, 16);

    inputFile.seekg(0, ios::end);
    streamsize remainingSize = inputFile.tellg();

    streamsize ciphertextStart = sizeof(FILE_HEADER) + sizeof(VERSION) + sizeof(extensionLength) + extensionLength + 16 + 16;
    ciphertext_len = remainingSize - ciphertextStart;
    
    inputFile.seekg(ciphertextStart, ios::beg);
    vector<unsigned char> ciphertext(ciphertext_len);

    inputFile.read((char*)ciphertext.data(), ciphertext_len);
    inputFile.close();

    derivekey(password, salt, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == nullptr)
    {
        cout<<"Failed to create decryption context!"<<endl;
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        cout<<"Failed to initialize decryption!"<<endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    vector<unsigned char> plaintext(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &plaintext_len, ciphertext.data(), ciphertext_len) != 1)
    {
        cout<<"Decryption failed!"<<endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    int final_len = 0;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &final_len) != 1)
    {
        cout<<endl;
        cout << "---------------------------------------------"<<endl;
        cout << "               ACCESS DENIED"<<endl;
        cout << "---------------------------------------------"<<endl;
        cout << "Incorrect password or corrupted encrypted file."<<endl;
        cout << "Decryption aborted."<<endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len += final_len;

    ofstream outFile("Output/decrypted." + extension, ios::binary);
    if (!outFile)
    {
        cout << "Failed to create decrypted file!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    outFile.write((char*)plaintext.data(), plaintext_len);
    outFile.close();

    EVP_CIPHER_CTX_free(ctx);
    cout<<endl;
    cout << "File decrypted successfully as decrypted." << extension << endl;
}
