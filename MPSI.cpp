#include "MPSI.h"
#include <chrono>
#include <iostream>

PSIOperations::PSIOperations(int t_val, int n_val, const PaillierPublicKey& pub_key) 
    : t(t_val), n(n_val), public_key(pub_key) {
    //threshold = 4 * t / 5;
    //tau_e = seq_public_key.encrypt(2 * threshold);
    
    data.resize(t, std::vector<mpz_class>(n));
    com.resize(t-1, std::vector<EncryptedNumber>(n));
    //Alpha.resize(t-1, std::vector<EncryptedNumber>(n));
    
    initializeData();
}

void PSIOperations::initializeData() {
    for (int j = 0; j < t-1; ++j) {
        for (int i = 0; i < n; ++i) {
            data[j][i] = mpz_class(i % 4);
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
    	std::cout<<"第"<<z<<"次实验"<<std::endl;
        zero = seq_public_key.encrypt(0);
        //std::cout<<"zero:"<<zero<<std::endl;
        intersection.clear();
        GBFs.clear();
        
        // Generate GBF for the first set
        auto time1 = std::chrono::high_resolution_clock::now();
        generateGarbledBloom(data[0], 0);
        auto time2 = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(time2 - time1);
        std::cout << "generate GBF time: " << duration.count() << "ms" << std::endl;
        std::cout <<75<<std::endl;
        // Generate GBF for the remaining t-2 sets
        for (int i = 1; i < t-1; ++i) {
            generateGarbledBloom(data[i], 0);
        }
        std::cout<<80<<std::endl;
        time1 = std::chrono::high_resolution_clock::now();
        
        // Compute beta values
        std::vector<EncryptedNumber> beta(n);
        std::cout<<85<<std::endl;
        for (int i = 0; i < n; ++i) {
            EncryptedNumber x = zero;  // Initialize with zero
            std::cout<<88<<std::endl;
            for (int j = 0; j < t-1; ++j) {
                //std::cout<<90<<std::endl;
                com[i][j] = queryGarbled(data[t-1][i], GBFs[j]);
                //std::cout<<com[i][j]<<std::endl;
                //std::cout<<92<<std::endl;
                x = x + com[i][j];  // Sum up the results
                //std::cout<<94<<std::endl;
            }
            std::cout<<96<<std::endl;
            std::cout << "x: " << seq_private_key.decrypt(x) << std::endl;  // Placeholder for printing x
            
            beta[i] = x;
            beta[i] = SEP_MPSI(beta[i], zero);
            
            std::cout << "beta: ";
            for (int k = 0; k < i+1; k++) {
                std::cout << seq_private_key.decrypt(beta[k]) << " ";
            }
            std::cout << std::endl;
            
            // If beta[i] == 2, add to intersection
            if (seq_private_key.decrypt(beta[i]) == 2) {
                intersection.push_back(data[t-1][i]);
            }
        }
        
        time2 = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(time2 - time1);
        
        std::cout << "compute time: " << duration.count() << "ms" << std::endl;
        std::cout << "Intersection: ";
        for (const auto& num : intersection) {
            std::cout << num.get_str() << " ";
        }
        std::cout << "\n\n";
    }
}
