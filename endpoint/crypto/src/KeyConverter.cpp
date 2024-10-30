#include <regex>

#include <privmx/crypto/ecc/ECC.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/crypto/KeyConverter.hpp"

using namespace privmx::endpoint::crypto;

std::string KeyConverter::cryptoKeyConvertPEMToWIF(const std::string& keyPEM) {
    std::string startMarker {"-----BEGIN EC PRIVATE KEY-----"};
    std::string endMarker {"-----END EC PRIVATE KEY-----"};
    
    std::size_t b64begin = keyPEM.find(startMarker);
    if (b64begin == std::string::npos) {
        throw privmx::crypto::UnsupportedKeyFormatException();
    }
    auto startPos = b64begin + startMarker.size() + 1;
    std::size_t b64end = keyPEM.find(endMarker, b64begin + startPos);
    if (b64end == std::string::npos) {
        throw privmx::crypto::UnsupportedKeyFormatException();
    }
    
    std::string base64 = keyPEM.substr(startPos, b64end - startPos);
    base64 = std::regex_replace(base64, std::regex("\n|\r|\t"), "");
    auto decoded = utils::Base64::toString(base64);
    std::string extractedKey {decoded.substr(7,32)};
    auto eccKey {privmx::crypto::ECC::fromPrivateKey(extractedKey)};
    auto privateKey {privmx::crypto::PrivateKey(eccKey)};
    auto wif {privateKey.toWIF()};
    return wif;
}
