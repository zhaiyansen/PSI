#include "PaillierCrypto.h"
#include "GarbledBloom.h"
#include <iostream>
#include <vector>
#include <string>

int main() {
    try {
        // 生成Paillier密钥对
        std::cout << "Generating Paillier key pair (1024 bits)..." << std::endl;
        PaillierKeyPair key_pair = PaillierKeyPair::generate(16);
        
        PaillierPublicKey public_key = key_pair.get_public_key();
        PaillierPrivateKey private_key = key_pair.get_private_key();
        
        std::cout << "Key generation complete." << std::endl;
        
        // 准备输入数据
        //std::vector<std::string> elements = {"apple", "banana", "cherry", "date", "elderberry","11","22"};
        std::vector<std::string> elements = {"11"};
        int n = elements.size();
        
        // 创建并生成Garbled Bloom Filter
        std::cout << "Generating Garbled Bloom Filter..." << std::endl;
        GarbledBloomFilter gbf(n, public_key);
        gbf.generate(elements,1);
        
        // 查询存在的元素
        std::cout << "查询存在的元素"<<std::endl;
        for (const auto& element : elements) {
            mpz_class result = gbf.query(element);
            //mpz_class decrypted = private_key.decrypt(result);
            mpz_class decrypted = private_key.decrypt(private_key.decrypt(result));
            std::cout << "Element: " << element << std::endl;
            std::cout << "Decrypted value: " << decrypted << std::endl;
            std::cout << "Is in set: " << (decrypted == 1 ? "Yes" : "No") << std::endl;
            std::cout << "-------------" << std::endl;
        }
        
        // 查询不存在的元素
        std::cout << "查询不存在的元素"<< std::endl;
        std::string nonExistingElement = "fig";
        mpz_class result = gbf.query(nonExistingElement);
        mpz_class decrypted = private_key.decrypt(private_key.decrypt(result));
        
        std::cout << "Element: " << nonExistingElement << std::endl;
        std::cout << "Decrypted value: " << decrypted << std::endl;
        std::cout << "Is in set: " << (decrypted == 1 ? "Yes" : "No") << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

