#include "seq.h"
#include <stdexcept>
#include <random>

// EncryptedNumber 实现
EncryptedNumber::EncryptedNumber(const mpz_class& ct, const PaillierPublicKey& pk)
    : ciphertext(ct), public_key(&pk) {}

EncryptedNumber EncryptedNumber::operator+(const EncryptedNumber& other) const {
    if (public_key != other.public_key) {
        throw std::runtime_error("Cannot add ciphertexts with different public keys");
    }
    mpz_class result = PaillierHomomorphic::add(*public_key, ciphertext, other.ciphertext);
    return EncryptedNumber(result, *public_key);
}

EncryptedNumber EncryptedNumber::operator*(const mpz_class& scalar) const {
    mpz_class result = PaillierHomomorphic::multiply_scalar(*public_key, ciphertext, scalar);
    return EncryptedNumber(result, *public_key);
}

EncryptedNumber EncryptedNumber::operator-() const {
    mpz_class neg_one = -1;
    return *this * neg_one;
}

// SEP_TMPSI 实现
EncryptedNumber SEP_TMPSI(const EncryptedNumber& x, const EncryptedNumber& y,
                         const PaillierPrivateKey& sk) {
    if (x.getPublicKey().get_n() != y.getPublicKey().get_n()) {
        throw std::runtime_error("Input ciphertexts must use same public key");
    }

    const PaillierPublicKey& pk = x.getPublicKey();
    mpz_class one = 1;
    EncryptedNumber enc_one = EncryptedNumber(pk.encrypt(one), pk);

    // 如果 x == y，直接返回 2 * enc_one
    EncryptedNumber diff = x + (-y);
    mpz_class diff_dec = sk.decrypt(diff.getCiphertext());
    if (diff_dec == 0) {
        return enc_one * 2; // 返回 2 表示相等
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1);
    int s1 = dis(gen) ? 1 : -1;
    int s2 = dis(gen) ? 1 : -1;

    mpz_class r1 = 2, r3 = 2;
    EncryptedNumber y_neg = -y;
    EncryptedNumber x_neg = -x;

    // a = ((x - y) * r1) * s1 + (-1 * s1)
    EncryptedNumber a = ((x + y_neg) * r1) * s1 + (EncryptedNumber(pk.encrypt(-s1), pk));
    
    // b = ((y - x) * r3) * s2 + (-1 * s2)
    EncryptedNumber b = ((y + x_neg) * r3) * s2 + (EncryptedNumber(pk.encrypt(-s2), pk));

    // 解密中间结果
    mpz_class a_dec = sk.decrypt(a.getCiphertext());
    mpz_class b_dec = sk.decrypt(b.getCiphertext());

    // 根据解密结果选择返回1或-1
    EncryptedNumber c = (a_dec > 0) ? EncryptedNumber(pk.encrypt(-s1), pk) : EncryptedNumber(pk.encrypt(s1), pk);
    EncryptedNumber d = (b_dec > 0) ? EncryptedNumber(pk.encrypt(-s2), pk) : EncryptedNumber(pk.encrypt(s2), pk);

    return c + d;
}



// SEP_MPSI 实现 
EncryptedNumber SEP_MPSI(const EncryptedNumber& x, const EncryptedNumber& y,
                        const PaillierPrivateKey& sk) {
    if (x.getPublicKey().get_n() != y.getPublicKey().get_n()) {
        throw std::runtime_error("Input ciphertexts must use same public key");
    }

    const PaillierPublicKey& pk = x.getPublicKey();
    mpz_class one = 1;
    EncryptedNumber enc_one = EncryptedNumber(pk.encrypt(one), pk);
    EncryptedNumber enc_one_neg = enc_one * (-1);

    // 随机选择 s1 和 s2
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1);
    int s1 = dis(gen) ? 1 : -1;
    int s2 = dis(gen) ? 1 : -1;

    mpz_class r1 = 2, r3 = 2;
    EncryptedNumber y_neg = y * (-1);
    EncryptedNumber x_neg = x * (-1);

    // 计算 a = ((x - y) * r1) * s1 + (-1 * s1)
    EncryptedNumber a = ((x + y_neg) * r1) * s1 + (EncryptedNumber(pk.encrypt(-s1), pk));
    
    // 计算 b = ((y - x) * r3) * s2 + (-1 * s2)
    EncryptedNumber b = ((y + x_neg) * r3) * s2 + (EncryptedNumber(pk.encrypt(-s2), pk));

    // 解密 a 和 b
    mpz_class a_dec = sk.decrypt(a.getCiphertext());
    mpz_class b_dec = sk.decrypt(b.getCiphertext());

    // 根据解密结果选择 c 和 d
    EncryptedNumber c = (a_dec > 0) ? enc_one_neg : enc_one;
    EncryptedNumber d = (b_dec > 0) ? enc_one_neg : enc_one;

    // 应用随机符号 s1 和 s2
    c = (s1 == -1) ? c * (-1) : c;
    d = (s2 == -1) ? d * (-1) : d;

    // 返回 c + d
    return c + d;
}


// SCP 函数实现
mpz_class SCP(const EncryptedNumber& x, const mpz_class& threshold,
             const PaillierPrivateKey& sk) {
    const PaillierPublicKey& pk = x.getPublicKey();
    mpz_class one = 1;
    EncryptedNumber enc_threshold = EncryptedNumber(pk.encrypt(threshold), pk);
    EncryptedNumber x_neg = -x;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1);
    int s3 = dis(gen) ? 1 : -1;

    mpz_class r3 = 2;
    mpz_class s3_mpz(s3);
    mpz_class neg_one_mpz(-1);
    
    // 首先计算 (enc_threshold + x_neg) * r3
    EncryptedNumber temp = (enc_threshold + x_neg) * r3;
    
    // 然后乘以 s3 (使用标量乘法)
    temp = temp * s3_mpz;
    
    // 最后加上 (-1 * s3) 的加密值
    EncryptedNumber enc_neg_s3 = EncryptedNumber(pk.encrypt(neg_one_mpz * s3_mpz), pk);
    EncryptedNumber f = temp + enc_neg_s3;

    mpz_class f_dec = sk.decrypt(f.getCiphertext());
    mpz_class g = (f_dec <= 0) ? one : -one;
    g = (s3 == -1) ? -g : g;

    return g;
}


