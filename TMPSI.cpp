#include "TMPSI.h"
#include <chrono>
#include <iostream>

PSIOperations::PSIOperations(int t_val, int n_val, const PaillierPublicKey& pub_key) 
    : t(t_val), n(n_val), public_key(pub_key) {
    threshold = 4 * t / 5;
    one = seq_public_key.encrypt(1);
    tau_e = seq_public_key.encrypt(2 * threshold);
    
    data.resize(t, std::vector<mpz_class>(n));
    com.resize(t-1, std::vector<EncryptedNumber>(n));
    Alpha.resize(t-1, std::vector<EncryptedNumber>(n));
    
    initializeData();
}

void PSIOperations::initializeData() {
    for (int j = 0; j < t-1; ++j) {
        for (int i = 0; i < n; ++i) {
            data[j][i] = mpz_class(i + j);
        }
    }
    
    for (int i = 0; i < n; ++i) {
        data[t-1][i] = mpz_class(2 * i);
    }
}

void PSIOperations::generateGarbledBloom(const std::vector<mpz_class>& input, int a) {
    std::vector<std::string> str_input;
    for (const auto& num : input) {
        str_input.push_back(num.get_str());
    }
    
    GarbledBloomFilter gbf(n, public_key);
    gbf.generate(str_input, a);
    GBFs.push_back(gbf);
}

EncryptedNumber PSIOperations::queryGarbled(const mpz_class& element, const GarbledBloomFilter& gbf) {
    std::string elem_str = element.get_str();
    mpz_class result = gbf.query(elem_str);
    //return seq_public_key.encrypt(result.get_si());
    return seq_public_key.encrypt(result);  // 直接加密 mpz_class

}

void PSIOperations::generateAllGBFs(int a) {
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 3; ++i) {
        generateGarbledBloom(data[i], a);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "generate GBF time: " << duration.count() << "ms" << std::endl;
        start = end;
    }
    
    for (int i = 3; i < t-1; ++i) {
        generateGarbledBloom(data[i], a);
    }
}

void PSIOperations::computeIntersection() {
    for (int z = 0; z < 3; ++z) {
        auto start = std::chrono::high_resolution_clock::now();
        intersection.clear();
        
        for (int i = 0; i < t-1; ++i) {
            for (int j = 0; j < n; ++j) {
                com[i][j] = queryGarbled(data[t-1][j], GBFs[i]);
                Alpha[i][j] = SEP_TMPSI(com[i][j], one);
            }
        }
        
        std::vector<EncryptedNumber> beta(n, seq_public_key.encrypt(0));
        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < t-1; ++j) {
                beta[i] = beta[i] + Alpha[j][i];
            }
            
            int result = SCP(beta[i], 2 * threshold);
            if (result == 1) {
                intersection.push_back(data[t-1][i]);
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        std::cout << "compute time: " << duration.count() << "ms" << std::endl;
        std::cout << "Intersection: ";
        for (const auto& num : intersection) {
            std::cout << num.get_str() << " ";
        }
        std::cout << "\n\n";
    }
}

