#include<iostream>
#include<iomanip>
#include<openssl/rand.h>
#include"crypto.h"
#include<fstream>

using namespace std;

unsigned char iv[16];

void generateIV()
{
    if (RAND_bytes(iv,sizeof(iv)) != 1)
    {
        cout<<"IV generation failed"<<endl;
        return;
    }
    cout<<endl;
    cout<<"Generated IV(16 bytes): "<<endl;
    for(int i = 0; i < sizeof(iv); i++)
    {
        cout<< hex << setw(2) << setfill('0') << (int)iv[i];
    }
    cout << dec << endl;
}
void generateSalt(unsigned char salt[16]) 
{
    if (RAND_bytes(salt, 16) != 1) 
    {
        cout << "Salt generation failed!" << endl;
        return;
    }
    cout << endl;
    cout << "Generated Salt : " << endl;
    for (int i = 0; i < 16; i++) 
    {
        cout << hex << setw(2) << setfill('0') << (int)salt[i];
    }
    cout << dec << endl;
}
