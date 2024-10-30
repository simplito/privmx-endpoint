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
