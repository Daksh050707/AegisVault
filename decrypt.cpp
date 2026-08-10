#include<iostream>
#include"decrypt.h"
#include<fstream>
#include<openssl/evp.h>
#include<cstring>
#include<vector>
#include "crypto.h"
#include"pbkdf2.h"

// Define the custom AegisVault file header and file format version

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

// Declare cryptographic variables required for decryption
// key  : Stores the AES-256 encryption key (32 bytes)
// salt : Stores the random salt used for PBKDF2 (16 bytes)
// iv   : Stores the AES Initialization Vector (16 bytes)

    unsigned char key[32];
    unsigned char salt[16];
    unsigned char iv[16];

    char header[sizeof(FILE_HEADER)];
    unsigned char version;

    unsigned char extensionLength;
    string extension;

// Take the decryption password from the user

    cout << "Enter password : ";
    cin >> password;

    int ciphertext_len = 0;

// Open the encrypted .aegis file    

    ifstream inputFile("Output/encrypted.aegis", ios::binary);
    if (!inputFile)
    {
        cout << "Encrypted file not found in the Output folder!" << endl;
        return;
    }

// Read the file header, version, and original file extension

    inputFile.read(header, sizeof(FILE_HEADER));
    inputFile.read((char*)&version, sizeof(version));

    inputFile.read((char*)&extensionLength, sizeof(extensionLength));

    char extensionBuffer[20];

    inputFile.read(extensionBuffer, extensionLength);

    extension.assign(extensionBuffer, extensionLength);

// Verify that the file is a valid AegisVault encrypted file

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

// Read the salt and Initialization Vector (IV)

    inputFile.read((char*)salt, 16);
    inputFile.read((char*)iv, 16);

// Calculate the size of the encrypted ciphertext

    inputFile.seekg(0, ios::end);
    streamsize remainingSize = inputFile.tellg();

    streamsize ciphertextStart = sizeof(FILE_HEADER) + sizeof(VERSION) + sizeof(extensionLength) + extensionLength + 16 + 16;
    ciphertext_len = remainingSize - ciphertextStart;
    
    inputFile.seekg(ciphertextStart, ios::beg);
    vector<unsigned char> ciphertext(ciphertext_len);

    inputFile.read((char*)ciphertext.data(), ciphertext_len);
    inputFile.close();

// Derive the AES-256 key from the password using PBKDF2

    derivekey(password, salt, key);

// Create the OpenSSL decryption context

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == nullptr)
    {
        cout<<"Failed to create decryption context!"<<endl;
        return;
    }

// Initialize AES-256-CBC decryption

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        cout<<"Failed to initialize decryption!"<<endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

// Decrypt the ciphertext into plaintext    

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
    
// Save the decrypted file using its original extension

    ofstream outFile("Output/decrypted." + extension, ios::binary);
    if (!outFile)
    {
        cout << "Failed to create decrypted file!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    outFile.write((char*)plaintext.data(), plaintext_len);
    outFile.close();

// Release the OpenSSL decryption context

    EVP_CIPHER_CTX_free(ctx);
    cout<<endl;
    cout << "File decrypted successfully as decrypted." << extension << endl;
}