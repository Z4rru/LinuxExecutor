#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace oss {

class Crypto {
public:
    static std::string sha256(const std::string& input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), 
               input.size(), hash);
        
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

    static std::vector<uint8_t> generate_key(size_t length = 32) {
        std::vector<uint8_t> key(length);
        if (RAND_bytes(key.data(), static_cast<int>(length)) != 1) {
            throw std::runtime_error("Failed to generate random key");
        }
        return key;
    }

    static std::vector<uint8_t> encrypt_aes256(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key
    ) {
        std::vector<uint8_t> iv(16);
        RAND_bytes(iv.data(), 16);

        auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
            EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free
        );

        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, 
                          key.data(), iv.data());

        std::vector<uint8_t> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH + 16);
        std::copy(iv.begin(), iv.end(), ciphertext.begin());

        int len = 0, total = 16;
        EVP_EncryptUpdate(ctx.get(), ciphertext.data() + total, &len,
                         plaintext.data(), static_cast<int>(plaintext.size()));
        total += len;
        
        EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + total, &len);
        total += len;

        ciphertext.resize(total);
        return ciphertext;
    }

    static std::vector<uint8_t> decrypt_aes256(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key
    ) {
        if (ciphertext.size() < 17) throw std::runtime_error("Invalid ciphertext");

        auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
            EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free
        );

        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                          key.data(), ciphertext.data());

        std::vector<uint8_t> plaintext(ciphertext.size());
        int len = 0, total = 0;
        
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                         ciphertext.data() + 16, 
                         static_cast<int>(ciphertext.size() - 16));
        total += len;

        EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total, &len);
        total += len;

        plaintext.resize(total);
        return plaintext;
    }

    static std::string base64_encode(const std::vector<uint8_t>& data) {
        static const char table[] = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        result.reserve(((data.size() + 2) / 3) * 4);
        
        for (size_t i = 0; i < data.size(); i += 3) {
            uint32_t n = static_cast<uint32_t>(data[i]) << 16;
            if (i + 1 < data.size()) n |= static_cast<uint32_t>(data[i+1]) << 8;
            if (i + 2 < data.size()) n |= static_cast<uint32_t>(data[i+2]);
            
            result += table[(n >> 18) & 0x3F];
            result += table[(n >> 12) & 0x3F];
            result += (i + 1 < data.size()) ? table[(n >> 6) & 0x3F] : '=';
            result += (i + 2 < data.size()) ? table[n & 0x3F] : '=';
        }
        return result;
    }
};

} // namespace oss