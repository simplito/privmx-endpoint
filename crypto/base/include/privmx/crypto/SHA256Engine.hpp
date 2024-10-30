#ifndef _PRIVMXLIB_CRYPTO_SHA256ENGINE_HPP_
#define _PRIVMXLIB_CRYPTO_SHA256ENGINE_HPP_

#include <Poco/Crypto/DigestEngine.h>

namespace privmx {
namespace crypto {

class SHA256Engine : public Poco::Crypto::DigestEngine
{
public:
    enum {
        BLOCK_SIZE = 64,
        DIGEST_SIZE = 32
    };

    SHA256Engine() : DigestEngine("SHA256") {}
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_SHA256ENGINE_HPP_
