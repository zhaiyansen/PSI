#include "PaillierCrypto.h"
#include <iostream>
#include <string>

int main() {
    try {
        std::cout << "Generating Paillier key pair (2048 bits)..." << std::endl;
        PaillierKeyPair key_pair = PaillierKeyPair::generate(2048);
        
        PaillierPublicKey public_key = key_pair.get_public_key();
        PaillierPrivateKey private_key = key_pair.get_private_key();
        
        std::cout << "Key generation complete." << std::endl;
        
        // 测试加密和解密
        mpz_class m1(123456);
        std::cout << "Original message m1: " << m1 << std::endl;
        
        mpz_class c1 = public_key.encrypt(m1);
        std::cout << "Encrypted c1: " << c1 << std::endl;
        
        mpz_class decrypted_m1 = private_key.decrypt(c1);
        std::cout << "Decrypted m1: " << decrypted_m1 << std::endl;
        
        // 测试同态加法
        mpz_class m2(78901);
        std::cout << "Original message m2: " << m2 << std::endl;
        
        mpz_class c2 = public_key.encrypt(m2);
        std::cout << "Encrypted c2: " << c2 << std::endl;
        
        mpz_class c_sum = PaillierHomomorphic::add(public_key, c1, c2);
        std::cout << "Encrypted sum c1+c2: " << c_sum << std::endl;
        
        mpz_class decrypted_sum = private_key.decrypt(c_sum);
        std::cout << "Decrypted sum: " << decrypted_sum << std::endl;
        std::cout << "Actual sum (m1+m2): " << (m1 + m2) << std::endl;
        
        // 测试标量乘法
        mpz_class scalar(5);
        std::cout << "Scalar value: " << scalar << std::endl;
        
        mpz_class c_product = PaillierHomomorphic::multiply_scalar(public_key, c1, scalar);
        std::cout << "Encrypted product c1*scalar: " << c_product << std::endl;
        
        mpz_class decrypted_product = private_key.decrypt(c_product);
        std::cout << "Decrypted product: " << decrypted_product << std::endl;
        std::cout << "Actual product (m1*scalar): " << (m1 * scalar) << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
