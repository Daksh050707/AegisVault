#ifndef PBKDF2_H
#define PBKDF2_H

#include <string>

void derivekey(const std :: string& password, const unsigned char salt[16], unsigned char key[32]);

#endif