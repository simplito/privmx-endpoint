#ifndef _PRIVMXLIB_CRYPTO_DRIVER_CRYPTOENV_HPP_
#define _PRIVMXLIB_CRYPTO_DRIVER_CRYPTOENV_HPP_

#include <privmx/crypto/CryptoEnv.hpp>
#include <privmx/utils/Types.hpp>

#include <Poco/SharedPtr.h>

namespace privmx {
namespace crypto {
namespace driverimpl {

class CryptoEnv : public privmx::crypto::CryptoEnv
{
public:
    using Ptr = Poco::SharedPtr<CryptoEnv>;

    static CryptoEnv::Ptr getEnv();
    CryptoEnv();
    CryptoService::Ptr getCryptoService() override;

private:
    CryptoService::Ptr _crypto_service;
    static utils::Mutex _mutex;
    static CryptoEnv::Ptr _env;
};

} // driverimpl
} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_DRIVER_CRYPTOENV_HPP_
