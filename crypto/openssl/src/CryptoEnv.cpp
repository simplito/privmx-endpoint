#include <privmx/crypto/openssl/CryptoEnv.hpp>
#include <privmx/crypto/openssl/CryptoService.hpp>
#include <privmx/crypto/CryptoConfig.hpp>

using namespace privmx;
using namespace privmx::crypto;

utils::Mutex opensslimpl::CryptoEnv::_mutex;
opensslimpl::CryptoEnv::Ptr opensslimpl::CryptoEnv::_env;

#ifdef PRIVMX_DEFAULT_CRYPTO_OPENSSL
CryptoEnv::Ptr CryptoEnv::getEnv() {
    return opensslimpl::CryptoEnv::getEnv();
}
#endif

opensslimpl::CryptoEnv::Ptr opensslimpl::CryptoEnv::getEnv() {
    utils::Lock lock(_mutex);
    if (_env.isNull()) {
        _env = CryptoEnv::Ptr(new opensslimpl::CryptoEnv());
    }
    return _env;
}

opensslimpl::CryptoEnv::CryptoEnv() {
    _crypto_service = CryptoService::Ptr(new opensslimpl::CryptoService());
}

CryptoService::Ptr opensslimpl::CryptoEnv::getCryptoService() {
    return _crypto_service;
}
