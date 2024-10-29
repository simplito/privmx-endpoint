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
