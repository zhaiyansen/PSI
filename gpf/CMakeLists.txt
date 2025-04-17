cmake_minimum_required(VERSION 3.10)
project(PaillierGarbledBloom)

set(CMAKE_CXX_STANDARD 17)

# 设置编译选项
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O2")

# 查找GMP、NTL和OpenSSL库
find_library(GMP_LIBRARY gmp)
find_library(GMPXX_LIBRARY gmpxx)
find_library(NTL_LIBRARY ntl)
find_package(OpenSSL REQUIRED)

# 添加源文件
add_executable(threshhold
    main.cpp
    PaillierCrypto.cpp
    GarbledBloom.cpp
    seq.cpp
)

# 包含头文件目录
target_include_directories(paillier_gbf_demo PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# 链接库
target_link_libraries(paillier_gbf_demo
    ${GMP_LIBRARY}
    ${GMPXX_LIBRARY}
    ${NTL_LIBRARY}
    ${OPENSSL_LIBRARIES}
)

