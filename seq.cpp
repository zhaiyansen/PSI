#include "seq.h"

// EncryptedNumber 运算符重载
EncryptedNumber EncryptedNumber::operator+(const EncryptedNumber& other) const {
    return EncryptedNumber(value + other.value);
}

EncryptedNumber EncryptedNumber::operator*(int scalar) const {
    return EncryptedNumber(value * scalar);
}

EncryptedNumber EncryptedNumber::operator-() const {
    return EncryptedNumber(-value);
}

// PublicKey 加密函数
EncryptedNumber PublicKey::encrypt(int value) {
    return EncryptedNumber(value);
}

// PrivateKey 解密函数
int PrivateKey::decrypt(const EncryptedNumber& num) {
    return num.value;
}

// SEP 函数实现
EncryptedNumber SEP(const EncryptedNumber& x, const EncryptedNumber& y) {
    PublicKey public_key;
    PrivateKey private_key;

    EncryptedNumber one = public_key.encrypt(1);
    EncryptedNumber one_ = -one;
    EncryptedNumber y_ = -y;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1);
    int s1 = dis(gen) ? 1 : -1;
    int s2 = dis(gen) ? 1 : -1;

    int r1 = 2, r3 = 2;
    EncryptedNumber x1 = -x;
    EncryptedNumber a = ((x + y_) * r1) * s1 + (-1 * s1);
    EncryptedNumber b = ((y + x1) * r3) * s2 + (-1 * s2);

    int a_text = private_key.decrypt(a);
    EncryptedNumber c_ = (a_text > 0) ? one_ : one;
    EncryptedNumber c = (s1 == -1) ? -c_ : c_;

    int b_text = private_key.decrypt(b);
    EncryptedNumber d_ = (b_text > 0) ? one_ : one;
    EncryptedNumber d = (s2 == -1) ? -d_ : d_;

    return c + d;
}

// SCP 函数实现
int SCP(const EncryptedNumber& x, int threshold) {
    PublicKey public_key;
    PrivateKey private_key;

    EncryptedNumber x_ = -x;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1);
    int s3 = dis(gen) ? 1 : -1;

    int r3 = 2;
    EncryptedNumber f = ((public_key.encrypt(threshold) + x_) * r3) * s3 + (-1 * s3);

    int f_text = private_key.decrypt(f);
    int g_ = (f_text <= 0) ? 1 : -1;
    int g = (s3 == -1) ? -g_ : g_;

    return g;
}

