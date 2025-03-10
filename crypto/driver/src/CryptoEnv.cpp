/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/driver/CryptoEnv.hpp>
#include <privmx/crypto/driver/CryptoService.hpp>
#include <privmx/crypto/CryptoConfig.hpp>

using namespace privmx;
using namespace privmx::crypto;

utils::Mutex driverimpl::CryptoEnv::_mutex;
driverimpl::CryptoEnv::Ptr driverimpl::CryptoEnv::_env;

#ifdef PRIVMX_DEFAULT_CRYPTO_DRIVER
CryptoEnv::Ptr CryptoEnv::getEnv() {
    return driverimpl::CryptoEnv::getEnv();
}
#endif

driverimpl::CryptoEnv::Ptr driverimpl::CryptoEnv::getEnv() {
    utils::Lock lock(_mutex);
    if (_env.isNull()) {
        _env = CryptoEnv::Ptr(new driverimpl::CryptoEnv());
    }
    return _env;
}

driverimpl::CryptoEnv::CryptoEnv() {
    _crypto_service = CryptoService::Ptr(new driverimpl::CryptoService());
}

CryptoService::Ptr driverimpl::CryptoEnv::getCryptoService() {
    return _crypto_service;
}
