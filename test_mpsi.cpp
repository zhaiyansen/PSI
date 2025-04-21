#include "TMPSI.h"
#include "PaillierCrypto.h"
#include <iostream>

int main() {
    try {
        // 1. 初始化参数
        const int t = 60;
        const int n = 1 << 2; // 64
        const int key_bits = 1024; // Paillier密钥长度

        std::cout << "=== MPSI Test ===" << std::endl;
        std::cout << "Parameters: t=" << t << ", n=" << n 
                  << ", key_bits=" << key_bits << std::endl;

        // 2. 生成Paillier密钥对
        std::cout << "\nGenerating Paillier keys..." << std::endl;
        auto start = std::chrono::high_resolution_clock::now();
        PaillierKeyPair keys = PaillierKeyPair::generate(key_bits);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Key generation time: " << duration.count() << "ms" << std::endl;

        // 3. 创建PSI操作实例
        std::cout << "\nInitializing PSI operations..." << std::endl;
        PSIOperations psi(t, n, keys.get_public_key());

        // 4. 生成所有GBF
        /*std::cout << "\nGenerating Garbled Bloom Filters..." << std::endl;
        psi.generateAllGBFs(0);
	*/
        // 5. 计算交集
        std::cout << "\nComputing intersection..." << std::endl;
        psi.computeIntersection();

        // 6. 获取并显示最终结果
        const std::vector<mpz_class>& intersection = psi.getIntersection();
        std::cout << "\nFinal intersection results (" << intersection.size() << " elements):" << std::endl;
        for (const auto& num : intersection) {
            std::cout << num.get_str() << " ";
        }
        std::cout << std::endl;

        // 7. 验证结果
        std::cout << "\nVerifying results..." << std::endl;
        if (!intersection.empty()) {
            std::cout << "First element: " << intersection[0].get_str() 
                      << ", Last element: " << intersection.back().get_str() << std::endl;
        } else {
            std::cout << "No intersection found." << std::endl;
        }

        std::cout << "\n=== Test Completed ===" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

