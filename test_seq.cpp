#include <iostream>
#include <gmpxx.h>
#include "seq.h"
#include "PaillierCrypto.h"

int main() {
    try {
        std::cout << "=== Paillier 加密系统测试 ===" << std::endl;
        
        // 1. 生成密钥对
        std::cout << "\n[1] 生成 1024 位 Paillier 密钥对..." << std::endl;
        PaillierKeyPair key_pair = PaillierKeyPair::generate(1024);
        PaillierPublicKey pk = key_pair.get_public_key();
        PaillierPrivateKey sk = key_pair.get_private_key();
        
        std::cout << "公钥 n: " << pk.get_n() << std::endl;
        std::cout << "私钥 p: " << sk.get_p() << std::endl;
        std::cout << "私钥 q: " << sk.get_q() << std::endl;

        // 2. 测试基本加密解密
        std::cout << "\n[2] 测试基本加密解密..." << std::endl;
        mpz_class plain1(42), plain2(123456789);
        
        // 修正：使用 EncryptedNumber 的构造函数
        EncryptedNumber enc1(pk.encrypt(plain1), pk);
        EncryptedNumber enc2(pk.encrypt(plain2), pk);
        
        mpz_class dec1 = sk.decrypt(enc1.getCiphertext());
        mpz_class dec2 = sk.decrypt(enc2.getCiphertext());
        
        std::cout << "明文1: " << plain1 << " -> 加密 -> 解密: " << dec1 << std::endl;
        std::cout << "明文2: " << plain2 << " -> 加密 -> 解密: " << dec2 << std::endl;

        // 3. 测试同态加法
        std::cout << "\n[3] 测试同态加法..." << std::endl;
        EncryptedNumber enc_sum = enc1 + enc2;
        mpz_class dec_sum = sk.decrypt(enc_sum.getCiphertext());
        
        std::cout << plain1 << " + " << plain2 << " = " << (plain1 + plain2) << std::endl;
        std::cout << "解密同态加法结果: " << dec_sum << std::endl;

        // 4. 测试标量乘法
        std::cout << "\n[4] 测试标量乘法..." << std::endl;
        mpz_class scalar(5);
        EncryptedNumber enc_scaled = enc1 * scalar;
        mpz_class dec_scaled = sk.decrypt(enc_scaled.getCiphertext());
        
        std::cout << plain1 << " * " << scalar << " = " << (plain1 * scalar) << std::endl;
        std::cout << "解密标量乘法结果: " << dec_scaled << std::endl;

        // 5. 测试 SEP_TMPSI (安全相等性测试)
        std::cout << "\n[5] 测试 SEP_TMPSI..." << std::endl;
        mpz_class plain3(42);  // 与 plain1 相同
        EncryptedNumber enc3(pk.encrypt(plain3), pk);
        
        std::cout << "比较 " << plain1 << " 和 " << plain2 << " (不同):" << std::endl;
        EncryptedNumber tmpsi_diff = SEP_TMPSI(enc1, enc2, sk);
        mpz_class tmpsi_diff_dec = sk.decrypt(tmpsi_diff.getCiphertext());
        std::cout << "结果: " << tmpsi_diff_dec << std::endl;
        
        std::cout << "比较 " << plain1 << " 和 " << plain3 << " (相同):" << std::endl;
        EncryptedNumber tmpsi_same = SEP_TMPSI(enc1, enc3, sk);
        mpz_class tmpsi_same_dec = sk.decrypt(tmpsi_same.getCiphertext());
        std::cout << "结果: " << tmpsi_same_dec << std::endl;

        // 6. 测试 SCP (安全比较协议)
        std::cout << "\n[6] 测试 SCP..." << std::endl;
        mpz_class threshold(100);
        
        std::cout << "比较 " << plain1 << " < " << threshold << ":" << std::endl;
        mpz_class scp_result1 = SCP(enc1, threshold, sk);
        std::cout << "结果: " << scp_result1 << std::endl;
        
        std::cout << "比较 " << plain2 << " < " << threshold << ":" << std::endl;
        mpz_class scp_result2 = SCP(enc2, threshold, sk);
        std::cout << "结果: " << scp_result2 << std::endl;

        // 7. 测试负数加密
        std::cout << "\n[7] 测试负数加密..." << std::endl;
        mpz_class negative_plain(-50);
        EncryptedNumber enc_neg(pk.encrypt(negative_plain), pk);
        mpz_class dec_neg = sk.decrypt(enc_neg.getCiphertext());
        
        std::cout << "负数明文: " << negative_plain << " -> 解密: " << dec_neg << std::endl;

        // 8. 测试大数加密
        std::cout << "\n[8] 测试大数加密..." << std::endl;
        mpz_class big_num("123456789012345678901234567890");
        EncryptedNumber enc_big(pk.encrypt(big_num), pk);
        mpz_class dec_big = sk.decrypt(enc_big.getCiphertext());
        
        std::cout << "大数明文: " << big_num << " -> 解密: " << dec_big << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\n=== 所有测试完成 ===" << std::endl;
    return 0;
}

