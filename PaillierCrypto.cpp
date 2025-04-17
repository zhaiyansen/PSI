#include "PaillierCrypto.h"
#include <iostream>
#include <cmath>
#include <NTL/ZZ.h>

// PaillierPublicKey implementation
PaillierPublicKey::PaillierPublicKey(const mpz_class& n) : n(n) {
    n_squared = n * n;
    g = n + 1; // 在Paillier系统中，通常g = n + 1是最简单的选择
}

mpz_class PaillierPublicKey::encrypt(const mpz_class& message, const mpz_class& r) const {
    if (message >= n) {
        throw std::runtime_error("Message is too large for the key modulus");
    }
    
    mpz_class random_r = r;
    if (r == 0) {
        // 如果没有提供随机数，则生成一个
        random_r = PaillierUtil::random_r(n);
    }
    
    return encrypt_raw(message, random_r);
}

mpz_class PaillierPublicKey::encrypt_raw(const mpz_class& message, const mpz_class& r) const {
    // 加密: g^m * r^n mod n^2
    mpz_class g_m;
    mpz_powm(g_m.get_mpz_t(), g.get_mpz_t(), message.get_mpz_t(), n_squared.get_mpz_t());
    
    mpz_class r_n;
    mpz_powm(r_n.get_mpz_t(), r.get_mpz_t(), n.get_mpz_t(), n_squared.get_mpz_t());
    
    mpz_class c = (g_m * r_n) % n_squared;
    return c;
}

int PaillierPublicKey::get_bit_length() const {
    return mpz_sizeinbase(n.get_mpz_t(), 2);
}

// PaillierPrivateKey implementation
PaillierPrivateKey::PaillierPrivateKey(const mpz_class& p, const mpz_class& q) 
    : p(p), q(q) {
    n = p * q;
    n_squared = n * n;
    compute_lambda();
    compute_mu();
}

void PaillierPrivateKey::compute_lambda() {
    mpz_class p_minus_1 = p - 1;
    mpz_class q_minus_1 = q - 1;
    lambda = PaillierUtil::lcm(p_minus_1, q_minus_1);
}

void PaillierPrivateKey::compute_mu() {
    // g = n + 1 的情况下，简化计算
    mpz_class g = n + 1;
    
    // 计算 L(g^lambda mod n^2) = (g^lambda mod n^2 - 1) / n
    mpz_class g_lambda;
    mpz_powm(g_lambda.get_mpz_t(), g.get_mpz_t(), lambda.get_mpz_t(), n_squared.get_mpz_t());
    mpz_class L_g_lambda = (g_lambda - 1) / n;
    
    // mu = L(g^lambda mod n^2)^(-1) mod n
    mu = PaillierUtil::invert(L_g_lambda, n);
}

mpz_class PaillierPrivateKey::decrypt(const mpz_class& ciphertext) const {
    // 解密: L(c^lambda mod n^2) * mu mod n
    // 其中 L(x) = (x - 1) / n
    
    mpz_class c_lambda;
    mpz_powm(c_lambda.get_mpz_t(), ciphertext.get_mpz_t(), lambda.get_mpz_t(), n_squared.get_mpz_t());
    
    mpz_class L_c_lambda = (c_lambda - 1) / n;
    mpz_class message = (L_c_lambda * mu) % n;
    
    return message;
}

// PaillierKeyPair implementation
PaillierKeyPair PaillierKeyPair::generate(int bits) {
    // 为了安全性，每个素数应该是密钥长度的一半
    int prime_size = bits / 2;
    
    mpz_class p, q;
    
    // 生成两个具有相同位长的质数
    do {
        p = PaillierUtil::generate_prime(prime_size);
        q = PaillierUtil::generate_prime(prime_size);
    } while (p == q || !PaillierUtil::is_coprime((p-1)*(q-1), p*q));
    
    PaillierPrivateKey private_key(p, q);
    PaillierPublicKey public_key = private_key.get_public_key();
    
    return PaillierKeyPair(public_key, private_key);
}

// PaillierHomomorphic implementation
mpz_class PaillierHomomorphic::add(const PaillierPublicKey& public_key, 
                                  const mpz_class& encrypted_a, 
                                  const mpz_class& encrypted_b) {
    return (encrypted_a * encrypted_b) % public_key.get_n_squared();
}

mpz_class PaillierHomomorphic::add_plain(const PaillierPublicKey& public_key, 
                                        const mpz_class& encrypted_a, 
                                        const mpz_class& plain_b) {
    mpz_class g_b;
    mpz_powm(g_b.get_mpz_t(), public_key.get_g().get_mpz_t(), 
             plain_b.get_mpz_t(), public_key.get_n_squared().get_mpz_t());
    
    return (encrypted_a * g_b) % public_key.get_n_squared();
}

mpz_class PaillierHomomorphic::multiply_scalar(const PaillierPublicKey& public_key, 
                                              const mpz_class& encrypted_a, 
                                              const mpz_class& scalar) {
    mpz_class result;
    mpz_powm(result.get_mpz_t(), encrypted_a.get_mpz_t(), 
             scalar.get_mpz_t(), public_key.get_n_squared().get_mpz_t());
    
    return result;
}

// PaillierUtil implementation
mpz_class PaillierUtil::generate_prime(int bits) {
    // 使用GMP库生成质数
    mpz_class prime;
    gmp_randclass rand(gmp_randinit_default);
    rand.seed(time(NULL) + clock());
    
    do {
        prime = rand.get_z_bits(bits);
        mpz_nextprime(prime.get_mpz_t(), prime.get_mpz_t());
    } while (mpz_sizeinbase(prime.get_mpz_t(), 2) != static_cast<size_t>(bits));
    
    return prime;
}

mpz_class PaillierUtil::invert(const mpz_class& a, const mpz_class& n) {
    mpz_class result;
    mpz_invert(result.get_mpz_t(), a.get_mpz_t(), n.get_mpz_t());
    return result;
}

mpz_class PaillierUtil::lcm(const mpz_class& a, const mpz_class& b) {
    mpz_class gcd, result;
    mpz_gcd(gcd.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    result = (a * b) / gcd;
    return result;
}

mpz_class PaillierUtil::random_r(const mpz_class& n) {
    gmp_randclass rand(gmp_randinit_default);
    rand.seed(time(NULL) + clock());
    
    mpz_class r;
    do {
        r = rand.get_z_range(n);
    } while (!is_coprime(r, n));
    
    return r;
}

bool PaillierUtil::is_coprime(const mpz_class& a, const mpz_class& b) {
    mpz_class gcd;
    mpz_gcd(gcd.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    return gcd == 1;
}

