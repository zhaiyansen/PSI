#ifndef PSI_OPERATIONS_H
#define PSI_OPERATIONS_H

#include <vector>
#include <cstdint>
#include "GarbledBloom.h"
#include "PaillierCrypto.h"
#include "seq.h"

class PSIOperations {
public:
    PSIOperations(int t_val, int n_val, const PaillierPublicKey& pub_key);
    
    void generateAllGBFs();
    void computeIntersection();
    const std::vector<mpz_class>& getIntersection() const { return intersection; }

private:
    int t;
    int n;
    int threshold;
    EncryptedNumber one;
    EncryptedNumber tau_e;
    
    std::vector<std::vector<mpz_class>> data;
    std::vector<std::vector<EncryptedNumber>> com;
    std::vector<std::vector<EncryptedNumber>> Alpha;
    
    std::vector<mpz_class> intersection;
    std::vector<GarbledBloomFilter> GBFs;
    
    PaillierPublicKey public_key;
    PublicKey seq_public_key;
    PrivateKey seq_private_key;

    void initializeData();
    void generateGarbledBloom(const std::vector<mpz_class>& input);
    EncryptedNumber queryGarbled(const mpz_class& element, const GarbledBloomFilter& gbf);
};

#endif // PSI_OPERATIONS_H

