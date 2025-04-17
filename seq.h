#ifndef SEQ_H
#define SEQ_H

#include <random>

class EncryptedNumber {
public:
    int value;
    EncryptedNumber(int v = 0) : value(v) {}
    EncryptedNumber operator+(const EncryptedNumber& other) const;
    EncryptedNumber operator*(int scalar) const;
    EncryptedNumber operator-() const;
};

class PublicKey {
public:
    EncryptedNumber encrypt(int value);
};

class PrivateKey {
public:
    int decrypt(const EncryptedNumber& num);
};

EncryptedNumber SEP(const EncryptedNumber& x, const EncryptedNumber& y);
int SCP(const EncryptedNumber& x, int threshold);

#endif // ENCRYPTED_OPERATIONS_H

