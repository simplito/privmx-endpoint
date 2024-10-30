#ifndef _PRIVMXLIB_CRYPTO_PUBLICKEY_HPP_
#define _PRIVMXLIB_CRYPTO_PUBLICKEY_HPP_

#include <string>

#include <privmx/crypto/ecc/ECC.hpp>

namespace privmx {
namespace crypto {

class PublicKey
{
public:
    static PublicKey fromDER(const std::string& der);
    static PublicKey fromBase58DER(const std::string& base58);
    PublicKey() = default;
    PublicKey(const ECC& key);
    bool operator==(const PublicKey& obj) const;
    bool operator!=(const PublicKey& obj) const;
    std::string toDER() const;
    std::string toBase58DER() const;
    std::string toBase58Address() const;
    bool verifyCompactSignature(const std::string& message, const std::string& signature) const;
    bool verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const;
    const ECC& getEcc() const;

private:
    ECC _key;
};

inline const ECC& PublicKey::getEcc() const {
    return _key;
}

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_PUBLICKEY_HPP_
