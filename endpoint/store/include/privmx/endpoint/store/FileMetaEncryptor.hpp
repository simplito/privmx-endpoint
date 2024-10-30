#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILEMETAENCRYPTOR_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILEMETAENCRYPTOR_HPP_

#include <string>

#include <privmx/crypto/CryptoPrivmx.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>

#include "privmx/endpoint/store/DynamicTypes.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class FileMetaEncryptor {
public:
    std::string signAndEncrypt(const dynamic::compat_v1::StoreFileMeta& data, const privmx::crypto::PrivateKey& priv, const std::string& key);
    FileMetaSigned decrypt(const std::string& data, const std::string& key);
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILEMETAENCRYPTOR_HPP_
