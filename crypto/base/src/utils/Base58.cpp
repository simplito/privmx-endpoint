#include <gmpxx.h>
#include <regex>

#include <privmx/utils/Base58.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/PrivmxException.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::utils;
using namespace std;

inline int count_first(char c, const string& s) {
    unsigned int i = 0;
    while (i < s.size() && s[i] == c)
        ++i;
    return i;
}

string Base58::encode(const string& s) {
    mpz_class x;
    mpz_import(x.get_mpz_t(), s.size(), 1, 1, 0, 0, s.data());
    string result = gmp2bitcoin( x.get_str(58) );
    if (unsigned int pad_size = count_first(0, s)) {
        string pad(pad_size, '1');
        return pad + result;
    } else {
        return result;
    }
}

string Base58::decode(const string& s) {
    mpz_class x(bitcoin2gmp(s), 58);
    size_t count = (mpz_sizeinbase(x.get_mpz_t(), 2) + 7) / 8;
    char data[count];
    mpz_export(data, &count, 1, 1, 0, 0, x.get_mpz_t());
    string result(data, count);
    if (int pad_size = count_first('1', s)) {
        string pad(pad_size, 0);
        return pad + result;
    } else {
        return result;
    }
}

string Base58::encodeWithChecksum(const string& s) {
    string checksum = Crypto::sha256(Crypto::sha256(s)).substr(0, 4);
    return encode(s + checksum);
}

string Base58::decodeWithChecksum(const string& s) {
    string data = decode(s);
    string payload = data.substr(0, data.length() - 4);
    string checksum = data.substr(data.length() - 4);
    string newchecksum = Crypto::sha256(Crypto::sha256(payload)).substr(0, 4);
    if (checksum != newchecksum) {
        throw PrivmxException("Invalid base58 checksum");
    }
    return payload;
}

bool Base58::is(const std::string& s) {
    std::regex base58Regex("^[A-HJ-NP-Za-km-z1-9]*={0,2}$");
    return std::regex_match(s, base58Regex);
}

string Base58::gmp2bitcoin(string s) {
    static const char map[] = {
        -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1, -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
        -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1, '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',  -1,  -1,  -1,  -1,  -1,  -1,
        -1, 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',  -1,  -1,  -1,  -1,  -1,
        -1, 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1 
    };
    for_each(s.begin(), s.end(), [](char& c) { c = map[reinterpret_cast<unsigned char&>(c)]; });
    return s;
}

string Base58::bitcoin2gmp(string s) {
    static const char map[] = {
        -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1, -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
        -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1, -1, '0', '1', '2', '3', '4', '5', '6', '7', '8',  -1,  -1,  -1,  -1,  -1,  -1,
        -1, '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',  -1, 'H', 'I', 'J', 'K', 'L',  -1, 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',  -1,  -1,  -1,  -1,  -1,
        -1, 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',  -1, 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',  -1,  -1,  -1,  -1,  -1
    };
    for_each(s.begin(), s.end(), [](char& c) { c = map[reinterpret_cast<unsigned char&>(c)]; });
    return s;
}
