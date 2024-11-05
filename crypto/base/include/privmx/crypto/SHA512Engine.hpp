/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_SHA512ENGINE_HPP_
#define _PRIVMXLIB_CRYPTO_SHA512ENGINE_HPP_

#include <Poco/Crypto/DigestEngine.h>

namespace privmx {
namespace crypto {

class SHA512Engine : public Poco::Crypto::DigestEngine
{
public:
    enum {
        BLOCK_SIZE = 128,
        DIGEST_SIZE = 64
    };

    SHA512Engine() : DigestEngine("SHA512") {}
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_SHA512ENGINE_HPP_
