/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_CRYPTOENV_HPP_
#define _PRIVMXLIB_CRYPTO_CRYPTOENV_HPP_

#include <privmx/crypto/CryptoService.hpp>

#include <Poco/SharedPtr.h>

namespace privmx {
namespace crypto {

class CryptoEnv
{
public:
    using Ptr = Poco::SharedPtr<CryptoEnv>;

    static CryptoEnv::Ptr getEnv();
    virtual ~CryptoEnv() = default;
    virtual CryptoService::Ptr getCryptoService() = 0;
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_CRYPTOENV_HPP_
