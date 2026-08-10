#ifndef CRYPTO_H
#define CRYPTO_H

extern unsigned char iv[16];

void generateIV();
void generateSalt(unsigned char salt[16]);

#endif