#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <unordered_map>

namespace oss {

class Crypto {
public:
    enum class HashAlgorithm {
        SHA256,
        SHA384,
        SHA512,
        SHA1,
        MD5
    };

    static HashAlgorithm parse_algorithm(const std::string& name) {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        static const std::unordered_map<std::string, HashAlgorithm> map = {
            {"sha256", HashAlgorithm::SHA256},
            {"sha-256", HashAlgorithm::SHA256},
            {"sha384", HashAlgorithm::SHA384},
            {"sha-384", HashAlgorithm::SHA384},
            {"sha512", HashAlgorithm::SHA512},
            {"sha-512", HashAlgorithm::SHA512},
            {"sha1", HashAlgorithm::SHA1},
            {"sha-1", HashAlgorithm::SHA1},
            {"md5", HashAlgorithm::MD5},
        };
        auto it = map.find(lower);
        if (it == map.end())
            throw std::runtime_error("Unsupported hash algorithm: " + name);
        return it->second;
    }

    static const EVP_MD* get_evp_md(HashAlgorithm algo) {
        switch (algo) {
            case HashAlgorithm::SHA256: return EVP_sha256();
            case HashAlgorithm::SHA384: return EVP_sha384();
            case HashAlgorithm::SHA512: return EVP_sha512();
            case HashAlgorithm::SHA1:   return EVP_sha1();
            case HashAlgorithm::MD5:    return EVP_md5();
        }
        return EVP_sha256();
    }

    static std::string hash(const std::string& input, HashAlgorithm algo = HashAlgorithm::SHA256) {
        const EVP_MD* md = get_evp_md(algo);
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;

        auto ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
            EVP_MD_CTX_new(), EVP_MD_CTX_free);

        if (!ctx) throw std::runtime_error("Failed to create hash context");

        if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1)
            throw std::runtime_error("Failed to init digest");
        if (EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1)
            throw std::runtime_error("Failed to update digest");
        if (EVP_DigestFinal_ex(ctx.get(), digest, &digest_len) != 1)
            throw std::runtime_error("Failed to finalize digest");

        return bytes_to_hex(digest, digest_len);
    }

    static std::string hash(const std::string& input, const std::string& algorithm) {
        return hash(input, parse_algorithm(algorithm));
    }

    static std::string sha256(const std::string& input) {
        return hash(input, HashAlgorithm::SHA256);
    }

    static std::string sha384(const std::string& input) {
        return hash(input, HashAlgorithm::SHA384);
    }

    static std::string sha512(const std::string& input) {
        return hash(input, HashAlgorithm::SHA512);
    }

    static std::string sha1(const std::string& input) {
        return hash(input, HashAlgorithm::SHA1);
    }

    static std::string md5(const std::string& input) {
        return hash(input, HashAlgorithm::MD5);
    }

    static std::string hmac(const std::string& input, const std::string& key,
                            HashAlgorithm algo = HashAlgorithm::SHA256) {
        const EVP_MD* md = get_evp_md(algo);
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;

        HMAC(md,
             key.data(), static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char*>(input.data()),
             input.size(),
             digest, &digest_len);

        return bytes_to_hex(digest, digest_len);
    }

    static std::vector<uint8_t> generate_key(size_t length = 32) {
        std::vector<uint8_t> key(length);
        if (RAND_bytes(key.data(), static_cast<int>(length)) != 1) {
            throw std::runtime_error("Failed to generate random key");
        }
        return key;
    }

    static std::vector<uint8_t> generate_bytes(size_t count) {
        std::vector<uint8_t> bytes(count);
        if (RAND_bytes(bytes.data(), static_cast<int>(count)) != 1) {
            throw std::runtime_error("Failed to generate random bytes");
        }
        return bytes;
    }

    static std::vector<uint8_t> encrypt_aes256(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key)
    {
        if (key.size() != 32)
            throw std::runtime_error("AES-256 requires a 32-byte key");

        std::vector<uint8_t> iv(16);
        if (RAND_bytes(iv.data(), 16) != 1)
            throw std::runtime_error("Failed to generate IV");

        auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
            EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                               key.data(), iv.data()) != 1)
            throw std::runtime_error("Failed to init encryption");

        std::vector<uint8_t> ciphertext(16 + plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        std::copy(iv.begin(), iv.end(), ciphertext.begin());

        int len = 0;
        int total = 16;

        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data() + total, &len,
                              plaintext.data(), static_cast<int>(plaintext.size())) != 1)
            throw std::runtime_error("Encryption update failed");
        total += len;

        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + total, &len) != 1)
            throw std::runtime_error("Encryption finalization failed");
        total += len;

        ciphertext.resize(total);
        return ciphertext;
    }

    static std::vector<uint8_t> encrypt_aes256(
        const std::string& plaintext,
        const std::vector<uint8_t>& key)
    {
        std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
        return encrypt_aes256(data, key);
    }

    static std::vector<uint8_t> decrypt_aes256(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key)
    {
        if (key.size() != 32)
            throw std::runtime_error("AES-256 requires a 32-byte key");
        if (ciphertext.size() < 17)
            throw std::runtime_error("Invalid ciphertext: too short");

        auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
            EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                               key.data(), ciphertext.data()) != 1)
            throw std::runtime_error("Failed to init decryption");

        std::vector<uint8_t> plaintext(ciphertext.size());
        int len = 0;
        int total = 0;

        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                              ciphertext.data() + 16,
                              static_cast<int>(ciphertext.size() - 16)) != 1)
            throw std::runtime_error("Decryption update failed");
        total += len;

        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total, &len) != 1)
            throw std::runtime_error("Decryption finalization failed (bad key or corrupted data)");
        total += len;

        plaintext.resize(total);
        return plaintext;
    }

    static std::string decrypt_aes256_string(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key)
    {
        auto plain = decrypt_aes256(ciphertext, key);
        return std::string(plain.begin(), plain.end());
    }

    static std::string base64_encode(const std::vector<uint8_t>& data) {
        static const char table[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        result.reserve(((data.size() + 2) / 3) * 4);

        for (size_t i = 0; i < data.size(); i += 3) {
            uint32_t n = static_cast<uint32_t>(data[i]) << 16;
            if (i + 1 < data.size()) n |= static_cast<uint32_t>(data[i + 1]) << 8;
            if (i + 2 < data.size()) n |= static_cast<uint32_t>(data[i + 2]);

            result += table[(n >> 18) & 0x3F];
            result += table[(n >> 12) & 0x3F];
            result += (i + 1 < data.size()) ? table[(n >> 6) & 0x3F] : '=';
            result += (i + 2 < data.size()) ? table[n & 0x3F] : '=';
        }
        return result;
    }

    static std::string base64_encode(const std::string& data) {
        return base64_encode(std::vector<uint8_t>(data.begin(), data.end()));
    }

    static std::vector<uint8_t> base64_decode(const std::string& encoded) {
        static const int lookup[256] = {
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
            52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
            15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
            -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
            41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
            -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        };

        std::vector<uint8_t> result;
        result.reserve(encoded.size() * 3 / 4);

        uint32_t accum = 0;
        int bits = 0;

        for (char c : encoded) {
            if (c == '=' || c == '\n' || c == '\r') continue;
            int val = lookup[static_cast<unsigned char>(c)];
            if (val < 0) throw std::runtime_error("Invalid base64 character");

            accum = (accum << 6) | static_cast<uint32_t>(val);
            bits += 6;

            if (bits >= 8) {
                bits -= 8;
                result.push_back(static_cast<uint8_t>((accum >> bits) & 0xFF));
            }
        }

        return result;
    }

    static std::string bytes_to_hex(const unsigned char* data, size_t len) {
        std::stringstream ss;
        for (size_t i = 0; i < len; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<int>(data[i]);
        }
        return ss.str();
    }

    static std::string bytes_to_hex(const std::vector<uint8_t>& data) {
        return bytes_to_hex(data.data(), data.size());
    }

    static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        if (hex.size() % 2 != 0)
            throw std::runtime_error("Invalid hex string: odd length");

        std::vector<uint8_t> result;
        result.reserve(hex.size() / 2);

        for (size_t i = 0; i < hex.size(); i += 2) {
            auto byte = static_cast<uint8_t>(
                std::stoi(hex.substr(i, 2), nullptr, 16));
            result.push_back(byte);
        }
        return result;
    }
};

} // namespace oss
