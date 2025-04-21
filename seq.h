#ifndef SEQ_H
#define SEQ_H

#include "PaillierCrypto.h"
#include <random>

class EncryptedNumber {
private:
    mpz_class ciphertext;
    const PaillierPublicKey* public_key; // 使用指针避免拷贝

public:
    EncryptedNumber(const mpz_class& ct, const PaillierPublicKey& pk);
    
    // 获取加密值和公钥
    const mpz_class& getCiphertext() const { return ciphertext; }
    const PaillierPublicKey& getPublicKey() const { return *public_key; }

    // 运算符重载
    EncryptedNumber operator+(const EncryptedNumber& other) const;
    EncryptedNumber operator*(const mpz_class& scalar) const;
    EncryptedNumber operator-() const;
};

// 安全比较协议函数
EncryptedNumber SEP_TMPSI(const EncryptedNumber& x, const EncryptedNumber& y,
                         const PaillierPrivateKey& sk);
EncryptedNumber SEP_MPSI(const EncryptedNumber& x, const EncryptedNumber& y,
                        const PaillierPrivateKey& sk);
mpz_class SCP(const EncryptedNumber& x, const mpz_class& threshold,
             const PaillierPrivateKey& sk);

#endif // SEQ_H

