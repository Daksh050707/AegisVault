#include<iostream>
#include<fstream>
#include<string>
#include<iterator>
#include<vector>
#include"encrypt.h"
#include<openssl/evp.h>
#include"crypto.h"
#include"pbkdf2.h"

const char FILE_HEADER[] = "AEGISVAULT";
const unsigned char VERSION = 2;

using namespace std;

void encryptFile()
{
    cout<<"---------------------------------------------------------------"<<endl;
    cout<<"                  ENCRYPTION MODULE STARTED!                   "<<endl;
    cout<<"---------------------------------------------------------------"<<endl;

    cout<<endl;

// Declare all variables required for encryption

    string filename;
    string extension;
    string content;
    string password;

    unsigned char key[32];
    unsigned char salt[16];

// Take filename from the user
    cout<<"Enter your file name with extension : ";
    cin>>filename;

 // Extract the file extension

    size_t dotPos = filename.find_last_of('.');
    if (dotPos == string::npos)
    {
        cout << "Please enter a valid filename with an extension." << endl;
        return;
    }
    extension = filename.substr(dotPos+1);

// Take the password from the user

    cout<<"Enter your password : ";
    cin>>password;

// This step is to open and read the input file

    ifstream file("Input/"+ filename, ios::binary);
    if(!file)
    {
        cout << "File not found in the Input folder!" << endl;
        return;
    }
    cout<<"Reading file..."<<endl;
    content.assign((istreambuf_iterator<char>(file)), (istreambuf_iterator<char>()));   
    file.close();

// Generate salt and derive AES-256 key using PBKDF2

    generateSalt(salt);
    derivekey(password, salt, key);

// Generate a random Initialization Vector (IV)

    generateIV();

// Create the OpenSSL encryption context

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if(ctx == nullptr)
    {
    cout<<"Failed to create encryption context!"<<endl;
    return;
    }

// Initialize AES-256-CBC encryption

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        cout<<"Encryption initialization failed!"<<endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

// Encrypt the file contents
    vector<unsigned char> ciphertext(content.size() + EVP_MAX_BLOCK_LENGTH);
    int ciphertext_len = 0;
    if(EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertext_len, (unsigned char*)content.data(), content.size()) != 1)
    {
        cout<<"Encryption failed!"<<endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    int final_len = 0;
    if(EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &final_len) != 1)
    {
        cout<<"Encryption finalization failed!"<<endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += final_len;
    ofstream outFile("Output/encrypted.aegis", ios::binary);
    if (!outFile)
    {
    cout << "Failed to create output file!" << endl;
    EVP_CIPHER_CTX_free(ctx);
    return;
    }

// Save encrypted data into .aegis file
    outFile.write(FILE_HEADER, sizeof(FILE_HEADER));
    outFile.write((char*)&VERSION, sizeof(VERSION));

    unsigned char extensionLength =
    static_cast<unsigned char>(extension.length());

    outFile.write((char*)&extensionLength, sizeof(extensionLength));
    outFile.write(extension.c_str(), extensionLength);

    outFile.write((char*)salt, 16);
    outFile.write((char*)iv, 16);
    outFile.write((char*)ciphertext.data(), ciphertext_len);

    outFile.close();

// Release the OpenSSL encryption context

    EVP_CIPHER_CTX_free(ctx);
    cout<<endl;
    cout<<"File encrypted successfully!"<<endl;
}