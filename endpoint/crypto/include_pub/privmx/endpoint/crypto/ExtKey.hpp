/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CRYPTO_EXTKEY_HPP_
#define _PRIVMXLIB_ENDPOINT_CRYPTO_EXTKEY_HPP_

#include <string>
#include <memory>


namespace privmx {
namespace crypto {
    class ExtKey;
} // crypto

namespace endpoint {
namespace crypto {

class ExtKey
{
public:
    static ExtKey fromSeed(const std::string& seed);
    static ExtKey fromBase58(const std::string& base58);
    static ExtKey generateRandom();
    ExtKey();
    ExtKey(const privmx::crypto::ExtKey& impl);

    ExtKey derive(uint32_t index) const;
    ExtKey deriveHardened(uint32_t index) const;
    std::string getPrivatePartAsBase58() const;
    std::string getPublicPartAsBase58() const;

    std::string getPrivateKey() const;
    std::string getPublicKey() const;
    std::string getPrivateEncKey() const;
    std::string getPublicKeyAsBase58Address() const;
    const std::string& getChainCode() const;
    bool verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const;
    bool isPrivate() const;

private:
    std::shared_ptr<privmx::crypto::ExtKey> _impl;
};

} // crypto
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CRYPTO_EXTKEY_HPP_
