/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/* Temporary classes to facilitate rewriting 
    from an old implementation to a new one   */


#include <memory>
#include <string>

#include "Base58.hpp"
#include "Utils.hpp"

#include "CryptoProviderFromDriver.hpp"

#include <gmpxx.h>
#include <regex>

namespace privmx {
namespace cryptoservice {
namespace ecc {

inline int count_first(char c, const std::string& s) {
    unsigned int i = 0;
    while (i < s.size() && s[i] == c)
        ++i;
    return i;
}

std::string Base58::encode(const std::string& s) {
    mpz_class x;
    mpz_import(x.get_mpz_t(), s.size(), 1, 1, 0, 0, s.data());
    std::string result = gmp2bitcoin( x.get_str(58) );
    if (unsigned int pad_size = count_first(0, s)) {
        std::string pad(pad_size, '1');
        return pad + result;
    } else {
        return result;
    }
}

std::string Base58::decode(const std::string& s) {
    mpz_class x(bitcoin2gmp(s), 58);
    size_t count = (mpz_sizeinbase(x.get_mpz_t(), 2) + 7) / 8;
    char data[count];
    mpz_export(data, &count, 1, 1, 0, 0, x.get_mpz_t());
    std::string result(data, count);
    if (int pad_size = count_first('1', s)) {
        std::string pad(pad_size, 0);
        return pad + result;
    } else {
        return result;
    }
}

std::string Base58::encodeWithChecksum(const std::string& s) {
    // std::string checksum = Crypto::sha256(Crypto::sha256(s)).substr(0, 4);
    std::string checksum = NewCrypto::digest(Hash::Sha256,NewCrypto::digest(Hash::Sha256,s)).substr(0, 4);
    return encode(s + checksum);
}

std::string Base58::decodeWithChecksum(const std::string& s) {
    std::string data = decode(s);
    std::string payload = data.substr(0, data.length() - 4);
    std::string checksum = data.substr(data.length() - 4);
    // std::string newchecksum = Crypto::sha256(Crypto::sha256(payload)).substr(0, 4);
    std::string newchecksum = NewCrypto::digest(Hash::Sha256, NewCrypto::digest(Hash::Sha256,payload)).substr(0, 4);
    if (checksum != newchecksum) {
        // throw PrivmxException("Invalid base58 checksum");
        throw std::runtime_error("Base58: Invalid base58 checksum");
    }
    return payload;
}

bool Base58::is(const std::string& s) {
    std::regex base58Regex("^[A-HJ-NP-Za-km-z1-9]*={0,2}$");
    return std::regex_match(s, base58Regex);
}

std::string Base58::gmp2bitcoin(std::string s) {
    static const char map[] = {
        -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1, -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
        -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1, '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',  -1,  -1,  -1,  -1,  -1,  -1,
        -1, 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',  -1,  -1,  -1,  -1,  -1,
        -1, 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1 
    };
    for_each(s.begin(), s.end(), [](char& c) { c = map[reinterpret_cast<unsigned char&>(c)]; });
    return s;
}

std::string Base58::bitcoin2gmp(std::string s) {
    static const char map[] = {
        -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1, -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
        -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, '0', '1', '2', '3', '4', '5', '6', '7', '8',  -1,  -1,  -1,  -1,  -1,  -1,
        -1, '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',  -1, 'H', 'I', 'J', 'K', 'L',  -1, 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',  -1,  -1,  -1,  -1,  -1,
        -1, 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',  -1, 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',  -1,  -1,  -1,  -1,  -1
    };
    for_each(s.begin(), s.end(), [](char& c) { c = map[reinterpret_cast<unsigned char&>(c)]; });
    return s;
}

inline int count_first_b(uint8_t c, BytesView s) {
    unsigned int i = 0;
    while (i < s.size() && s[i] == c)
        ++i;
    return i;
}


Bytes Base58::encodeB(BytesView s) {
    mpz_class x;
    mpz_import(x.get_mpz_t(), s.size(), 1, 1, 0, 0, s.data());
    // Bytes result = Utils::s2b(gmp2bitcoin( x.get_str(58)));
    Bytes result = gmp2bitcoinB(Utils::s2b(x.get_str(58)));
    if (unsigned int pad_size = count_first_b(0, s)) {
        result.insert(result.begin(), pad_size, (uint8_t) '1');        
    } 
    return result;
}

Bytes Base58::decodeB(BytesView s) {
    // mpz_class x(bitcoin2gmp(Utils::b2s(s)), 58);
    mpz_class x(Utils::b2s(bitcoin2gmpB(Bytes(s.begin(),s.end()))), 58);
    size_t count = (mpz_sizeinbase(x.get_mpz_t(), 2) + 7) / 8;
    uint8_t data[count];
    mpz_export(data, &count, 1, 1, 0, 0, x.get_mpz_t());
    Bytes result(data, data+count);
    if (int pad_size = count_first_b((uint8_t) '1', s)) {
        result.insert(result.begin(), pad_size, (uint8_t) 0);        
    } 
    return result;
}

Bytes Base58::encodeWithChecksumB(std::shared_ptr<IDigest> p, BytesView data) {
    Bytes checksum = p.get()->digest(Hash::Sha256,p.get()->digest(Hash::Sha256,data));
    if (checksum.size() > 4) checksum.resize(4);
    Bytes dataWithChecksum(data.begin(),data.end());
    dataWithChecksum.reserve(dataWithChecksum.size() + checksum.size());
    dataWithChecksum.insert(dataWithChecksum.end(),checksum.begin(),checksum.end());
    return encodeB(dataWithChecksum);
}

Bytes Base58::decodeWithChecksumB(std::shared_ptr<IDigest> p, BytesView encodedData) {
    Bytes data = decodeB(encodedData);
    Bytes payload(data.begin(), data.begin() + (data.size() - 4));
    Bytes checksum(data.begin() + (data.size() - 4), data.end());
    Bytes newchecksum = p.get()->digest(Hash::Sha256,p.get()->digest(Hash::Sha256,payload));
    if (newchecksum.size() > 4) newchecksum.resize(4);
    if (checksum != newchecksum) {
        // throw PrivmxException("Invalid base58 checksum");
        throw std::runtime_error("Base58: Invalid base58 checksum:"
        //     " [" + Utils::b2s(checksum) + "] vs [" + Utils::b2s(newchecksum) + "]"
        );
    }
    return payload;
}

Bytes Base58::gmp2bitcoinB(Bytes s) {
    static const uint8_t map[] = {
        0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF, 0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,
        0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF, '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,
        0xFF, 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,
        0xFF, 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF 
    };
    for_each(s.begin(), s.end(), [](uint8_t& c) { c = map[c]; });
    return s;
}

Bytes Base58::bitcoin2gmpB(Bytes s) {
    static const uint8_t map[] = {
        0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF, 0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,
        0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF, 0xFF, '0', '1', '2', '3', '4', '5', '6', '7', '8',  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,
        0xFF, '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',  0xFF, 'H', 'I', 'J', 'K', 'L',  0xFF, 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',  0xFF,  0xFF,  0xFF,  0xFF,  0xFF,
        0xFF, 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',  0xFF, 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',  0xFF,  0xFF,  0xFF,  0xFF,  0xFF
    };
    for_each(s.begin(), s.end(), [](uint8_t& c) { c = map[c]; });
    return s;
}

inline bool Base58::isB(BytesView s) { return is(Utils::b2s(s)); }

} // ecc
} // cryptoservice
} // privmx
