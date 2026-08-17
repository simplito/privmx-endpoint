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


} // ecc
} // cryptoservice
} // privmx
