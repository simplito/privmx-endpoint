/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_ECCIMPL_HPP_
#define _PRIVMXLIB_CRYPTO_ECCIMPL_HPP_

#include <string>
#include <Poco/SharedPtr.h>

namespace privmx {
namespace crypto {

/**
 * @brief The EC key operations a backend has to provide.
 *
 * Everything here returns a string, deliberately. Accessors handing out big numbers and curve
 * points used to sit beside these, and they forced every implementation to expose one library's
 * representation of those; nothing outside the backend ever called them.
 *
 * One consequence is easy to miss and is load-bearing: `getPrivateKey` returns the scalar as a
 * **big number**, so leading zeros are absent. `ExtKey` depends on it — see the branch there that
 * picks between padding to 32 bytes and hashing the bytes exactly as returned.
 */
class ECCImpl
{
public:
    using Ptr = Poco::SharedPtr<ECCImpl>;

    static ECCImpl::Ptr genPair();
    static ECCImpl::Ptr fromPublicKey(const std::string& public_key);
    static ECCImpl::Ptr fromPrivateKey(const std::string& private_key);
    virtual ~ECCImpl() = default;
    virtual operator bool() const = 0;
    virtual bool isEmpty() const = 0;
    virtual std::string getPublicKey(bool compact = true) const = 0;
    virtual std::string getPrivateKey() const = 0;
    virtual std::string sign(const std::string& data) const = 0;
    virtual bool verify(const std::string& data, const std::string& signature) const = 0;
    virtual std::string derive(const ECCImpl::Ptr ecc) const = 0;
    virtual bool hasPrivate() const = 0;
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_ECCIMPL_HPP_
