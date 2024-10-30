#ifndef _PRIVMXLIB_CRYPTO_ECIES_HPP_
#define _PRIVMXLIB_CRYPTO_ECIES_HPP_

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>

namespace privmx {
namespace crypto {

class ECIES
{
public:
    ECIES(const PrivateKey& private_key, const PublicKey& public_key);
    std::string decrypt(const std::string& enc_buf) const;
    std::string encrypt(const std::string& data) const;

private:
    std::string getM() const;
    std::string getE() const;

    std::string _shared_key;
    std::string _private_enc_key;
};

inline std::string ECIES::getM() const {
    return _shared_key.substr(32, 32);
}

inline std::string ECIES::getE() const {
    return _shared_key.substr(0, 32);
}

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_ECIES_HPP_
