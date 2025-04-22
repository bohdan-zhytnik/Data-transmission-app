// SHA256.cpp
#include "SHA256.h"
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

std::string compute_sha256(const std::string& file_path) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX.");
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed.");
    }
    std::ifstream file(file_path, std::ifstream::binary);
    if(!file) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Cannot open file for SHA-256 computation.");
    }
    char buffer[1024];
    // while(file.good()) {
    //     file.read(buffer, sizeof(buffer));
    //     if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
    //         EVP_MD_CTX_free(mdctx);
    //         throw std::runtime_error("EVP_DigestUpdate failed.");
    //     }
    // }
    while(true) {
        file.read(buffer, sizeof(buffer));
        std::streamsize bytes_read = file.gcount();
        if (bytes_read <= 0) {
            break;
        }

        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("EVP_DigestUpdate failed.");
        }

        if (file.eof()) {
            break;
        }
    }




    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed.");
    }

    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for(unsigned int i = 0; i < hash_len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}
