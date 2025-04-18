#include "GarbledBloom.h"
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>

GarbledBloomFilter::GarbledBloomFilter(int numElements, const PaillierPublicKey& pubKey) 
    : publicKey(pubKey) {
    // 使用与Python相同的公式计算Bloom filter大小
    m = static_cast<int>((10.0 * numElements) / 0.69);
    lambda = 2048;
    garbledBloomArray.resize(m);
}

// 使用OpenSSL的EVP接口替代弃用的函数
std::string computeHash(const std::string& input, const std::string& algorithm) {
    const EVP_MD* md = nullptr;
    
    if (algorithm == "md5") {
        md = EVP_md5();
    } else if (algorithm == "sha1") {
        md = EVP_sha1();
    } else if (algorithm == "sha224") {
        md = EVP_sha224();
    } else if (algorithm == "sha256") {
        md = EVP_sha256();
    } else if (algorithm == "sha384") {
        md = EVP_sha384();
    } else if (algorithm == "sha512") {
        md = EVP_sha512();
    } else if (algorithm == "sha3_224") {
        md = EVP_sha3_224();
    } else if (algorithm == "sha3_256") {
        md = EVP_sha3_256();
    } else if (algorithm == "sha3_384") {
        md = EVP_sha3_384();
    } else if (algorithm == "sha3_512") {
        md = EVP_sha3_512();
    } else {
        // 默认使用SHA-256
        md = EVP_sha256();
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    
    return std::string(reinterpret_cast<char*>(hash), hash_len);
}

// 将哈希转换为十六进制字符串
std::string bytesToHexString(const std::string& input) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : input) {
        ss << std::setw(2) << (static_cast<int>(byte) & 0xff);
    }
    return ss.str();
}

std::vector<size_t> GarbledBloomFilter::computeHashes(const std::string& element) const {
    std::vector<size_t> hashPositions;
    
    // 定义与Python相同的哈希函数
    std::vector<std::string> hashAlgorithms = {
        "md5", "sha224", "sha256", "sha1", "sha384", "sha512",
        "sha3_224", "sha3_256", "sha3_384", "sha3_512"
    };
    
    for (const auto& algorithm : hashAlgorithms) {
        std::string hash = computeHash(element, algorithm);
        std::string hexHash = bytesToHexString(hash);
        
        // 将十六进制字符串转换为整数并对m取模
        size_t hashValue = 0;
        // 直接使用哈希值的字节数组计算整数
        for (size_t i = 0; i < hash.size(); ++i) {
            hashValue = (hashValue << 8) | static_cast<unsigned char>(hash[i]);
        }
        
        hashPositions.push_back(hashValue % m);
    }
    
    return hashPositions;
}

mpz_class GarbledBloomFilter::generateRandomBits(int bits) const {
    static std::mt19937_64 rng(std::random_device{}());
    static std::uniform_int_distribution<unsigned long long> dist;
    
    mpz_class result;
    int generated = 0;
    
    while (generated < bits) {
        unsigned long long random_value = dist(rng);
        
        // 使用 GMP 函数来设置值
        mpz_class temp;
        mpz_import(temp.get_mpz_t(), 1, 1, sizeof(random_value), 0, 0, &random_value);
        
        result = (result << 64) | temp;
        generated += 64;
    }
    
    // 确保我们只保留'bits'位
    if (generated > bits) {
        mpz_class mask = (mpz_class(1) << bits) - 1;
        result &= mask;
    }
    
    return result;
}


void GarbledBloomFilter::generate(const std::vector<std::string>& inputArray) {
    //调试信息
    //std::cout << "Generating Garbled Bloom Filter with " << inputArray.size() << " elements..." << std::endl;
    // 初始化所有位置为空
    for (int i = 0; i < m; i++) {
        garbledBloomArray[i] = 0;
    }
    
    for (const auto& element : inputArray) {
        // 加密数字1，对应Python代码中的 one = public_key.encrypt(1)
        mpz_class one_text = publicKey.encrypt(1);
        /*mpz_class one_text;
	try {
	    one_text = publicKey.encrypt(1);
	} catch (const std::exception& e) {
	    std::cerr << "Encryption failed: " << e.what() << std::endl;
	    throw;
	} */

        
        int emptySlot = -1;
        mpz_class finalShare = one_text;
        
        // 计算哈希
        std::vector<size_t> hashPositions = computeHashes(element);
        
        for (size_t i = 0; i < hashPositions.size(); i++) {
            size_t j = hashPositions[i];
            
            if (garbledBloomArray[j] == 0) {
                if (emptySlot == -1) {
                    emptySlot = j;  // 预留空槽位用于最终的share
                } else {
                    mpz_class newShare = generateRandomBits(lambda);
                    garbledBloomArray[j] = newShare;
                    // XOR操作对应大整数的按位异或
                    finalShare = finalShare ^ garbledBloomArray[j];
                }
            } else {
                finalShare = finalShare ^ garbledBloomArray[j];
            }
        }
        
        // 在空槽放入最终的share
        if (emptySlot != -1) {
            garbledBloomArray[emptySlot] = finalShare;
        }
    }
    
    // 填充所有剩余的空槽
    for (int i = 0; i < m; i++) {
        if (garbledBloomArray[i] == 0) {
            garbledBloomArray[i] = generateRandomBits(lambda);
        }
    }
}

mpz_class GarbledBloomFilter::query(const std::string& element) const {
    std::vector<size_t> hashPositions = computeHashes(element);
    
    mpz_class recovered = 0;
    for (const auto& j : hashPositions) {
        recovered = recovered ^ garbledBloomArray[j];
    }
    
    return recovered;
}

