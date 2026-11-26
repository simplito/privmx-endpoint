/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/pmxcrypto/CryptoEnv.hpp>
#include <privmx/crypto/pmxcrypto/CryptoService.hpp>

using namespace privmx;
using namespace privmx::crypto;

utils::Mutex pmximpl::CryptoEnv::_mutex;
pmximpl::CryptoEnv::Ptr pmximpl::CryptoEnv::_env;

// The definition of the base factory, which is what decides the backend at link time. Exactly one
// translation unit may define it; with pmx-crypto the only backend, this is that one.
CryptoEnv::Ptr CryptoEnv::getEnv() {
    return pmximpl::CryptoEnv::getEnv();
}

pmximpl::CryptoEnv::Ptr pmximpl::CryptoEnv::getEnv() {
    utils::Lock lock(_mutex);
    if (_env.isNull()) {
        _env = CryptoEnv::Ptr(new pmximpl::CryptoEnv());
    }
    return _env;
}

pmximpl::CryptoEnv::CryptoEnv() {
    _crypto_service = CryptoService::Ptr(new pmximpl::CryptoService());
}

CryptoService::Ptr pmximpl::CryptoEnv::getCryptoService() {
    return _crypto_service;
}
