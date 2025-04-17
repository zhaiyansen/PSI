#ifndef GARBLED_BLOOM_H
#define GARBLED_BLOOM_H

#include "PaillierCrypto.h"
#include <vector>
#include <string>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <random>
#include <iostream>
#include <cstring>

class GarbledBloomFilter {
public:
    GarbledBloomFilter(int numElements, const PaillierPublicKey& pubKey);
    
    // 生成Garbled Bloom Filter
    void generate(const std::vector<std::string>& inputArray);
    
    // 查询Garbled Bloom Filter
    mpz_class query(const std::string& element) const;
    
    // 获取整个Garbled Bloom Filter
    const std::vector<mpz_class>& getFilter() const { return garbledBloomArray; }

private:
    int m; // Bloom filter大小
    int lambda; // 随机数位长度
    std::vector<mpz_class> garbledBloomArray;
    PaillierPublicKey publicKey;
    
    // 计算元素的多个哈希值
    std::vector<size_t> computeHashes(const std::string& element) const;
    
    // 生成随机数
    mpz_class generateRandomBits(int bits) const;
};

#endif // GARBLED_BLOOM_H

