#ifndef PAILLIER_CRYPTO_H
#define PAILLIER_CRYPTO_H

#include <gmpxx.h>
#include <NTL/ZZ.h>
#include <string>
#include <vector>
#include <random>
#include <ctime>

class PaillierPublicKey {
public:
    PaillierPublicKey(const mpz_class& n);
    mpz_class encrypt(const mpz_class& message, const mpz_class& r = 0) const;
    mpz_class encrypt_raw(const mpz_class& message, const mpz_class& r) const;
    mpz_class get_n() const { return n; }
    mpz_class get_n_squared() const { return n_squared; }
    mpz_class get_g() const { return g; }
    int get_bit_length() const;

private:
    mpz_class n;
    mpz_class n_squared;
    mpz_class g;  // 通常 g = n + 1
};

class PaillierPrivateKey {
public:
    PaillierPrivateKey(const mpz_class& p, const mpz_class& q);
    mpz_class decrypt(const mpz_class& ciphertext) const;
    PaillierPublicKey get_public_key() const { return PaillierPublicKey(p * q); }
    mpz_class get_p() const { return p; }
    mpz_class get_q() const { return q; }

private:
    mpz_class p;
    mpz_class q;
    mpz_class n;
    mpz_class n_squared;
    mpz_class lambda;
    mpz_class mu;
    
    void compute_lambda();
    void compute_mu();
};

class PaillierKeyPair {
public:
    PaillierKeyPair(const PaillierPublicKey& public_key, const PaillierPrivateKey& private_key)
        : public_key(public_key), private_key(private_key) {}
    
    PaillierPublicKey get_public_key() const { return public_key; }
    PaillierPrivateKey get_private_key() const { return private_key; }

    static PaillierKeyPair generate(int bits);

private:
    PaillierPublicKey public_key;
    PaillierPrivateKey private_key;
};

// 同态操作函数
namespace PaillierHomomorphic {
    // 密文加法：E(a) * E(b) = E(a+b)
    mpz_class add(const PaillierPublicKey& public_key, 
                 const mpz_class& encrypted_a, 
                 const mpz_class& encrypted_b);
    
    // 密文与明文加法：E(a) * g^b = E(a+b)
    mpz_class add_plain(const PaillierPublicKey& public_key, 
                        const mpz_class& encrypted_a, 
                        const mpz_class& plain_b);
    
    // 密文乘标量：E(a)^b = E(a*b)
    mpz_class multiply_scalar(const PaillierPublicKey& public_key, 
                             const mpz_class& encrypted_a, 
                             const mpz_class& scalar);
}

// 工具函数
namespace PaillierUtil {
    mpz_class generate_prime(int bits);
    mpz_class invert(const mpz_class& a, const mpz_class& n);
    mpz_class lcm(const mpz_class& a, const mpz_class& b);
    mpz_class random_r(const mpz_class& n);
    bool is_coprime(const mpz_class& a, const mpz_class& b);
}

#endif // PAILLIER_CRYPTO_H

