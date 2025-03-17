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
#include <privmx/endpoint/core/Buffer.hpp>


namespace privmx {
namespace crypto {
    class ExtKey;
} //crypto

namespace endpoint {
namespace crypto {
/**
 * 'ExtKey' is a class representing Extended keys and operations on it.
 */
class ExtKey
{
public:
    /**
     * Creates ExtKey from given seed.
     * @param seed the seed used to generate Key
     * @return ExtKey object
    */
    static ExtKey fromSeed(const core::Buffer& seed);
    /**
     * Decodes ExtKey from Base58 format.
     *
     * @param base58 the ExtKey in Base58
     * @return ExtKey object
    */
    static ExtKey fromBase58(const std::string& base58);
    /**
     * Generates a new ExtKey.
     *
     * @return ExtKey object
    */
    static ExtKey generateRandom();
    /**
     * //doc-gen:ignore
     */
    ExtKey();
    /**
     * //doc-gen:ignore
     */
    ExtKey(const privmx::crypto::ExtKey& impl);

    /**
     * Generates child ExtKey from a current ExtKey using BIP32.
     *
     * @param index number from 0 to 2^31-1

     * @return ExtKey object 
     */
    ExtKey derive(uint32_t index) const;

    /**
     * Generates hardened child ExtKey from a current ExtKey using BIP32.
     *
     * @param index number from 0 to 2^31-1

     * @return ExtKey object 
     */
    ExtKey deriveHardened(uint32_t index) const;

    /**
     * Converts ExtKey to Base58 string.
     *
     * @return ExtKey in Base58 format
    */
    std::string getPrivatePartAsBase58() const;

    /**
     * Converts the public part of ExtKey to Base58 string.
     *
     * @return ExtKey in Base58 format
    */
    std::string getPublicPartAsBase58() const;

    /**
     * Extracts ECC PrivateKey.
     *
     * @return ECC key in WIF format
    */
    std::string getPrivateKey() const;

    /**
     * Extracts ECC PublicKey.
     *
     * @return ECC key in BASE58DER format
    */
    std::string getPublicKey() const;

    /**
     * Extracts raw ECC PrivateKey.
     *
     * @return ECC PrivateKey 
    */
    core::Buffer getPrivateEncKey() const;

    /**
     * Extracts ECC PublicKey Address.
     *
     * @return ECC Address in BASE58 format
    */
    std::string getPublicKeyAsBase58Address() const;

    /**
     * @brief Gets the chain code of Extended Key.
     * 
     * @return Raw chain code
     */
    core::Buffer getChainCode() const;

    /**
     * @brief Validates a signature of a message.
     * 
     * @param message data used on validation
     * @param signature signature of data to verify
     * @return message validation result
     */
    bool verifyCompactSignatureWithHash(const core::Buffer& message, const core::Buffer& signature) const;
    /**
     * Checks if ExtKey is Private.
     *
     * @return returns true if ExtKey is private
    */
    bool isPrivate() const;

private:
    std::shared_ptr<privmx::crypto::ExtKey> _impl;
};

} // crypto
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CRYPTO_EXTKEY_HPP_
