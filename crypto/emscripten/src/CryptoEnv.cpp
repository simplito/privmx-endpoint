/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/emscripten/CryptoEnv.hpp>
#include <privmx/crypto/emscripten/CryptoService.hpp>
#include <privmx/crypto/CryptoConfig.hpp>

using namespace privmx;
using namespace privmx::crypto;

utils::Mutex emscriptenimpl::CryptoEnv::_mutex;
emscriptenimpl::CryptoEnv::Ptr emscriptenimpl::CryptoEnv::_env;

#ifdef PRIVMX_DEFAULT_CRYPTO_EMSCRIPTEN
CryptoEnv::Ptr CryptoEnv::getEnv() {
    return emscriptenimpl::CryptoEnv::getEnv();
}
#endif

emscriptenimpl::CryptoEnv::Ptr emscriptenimpl::CryptoEnv::getEnv() {
    utils::Lock lock(_mutex);
    if (_env.isNull()) {
        _env = CryptoEnv::Ptr(new emscriptenimpl::CryptoEnv());
    }
    return _env;
}

emscriptenimpl::CryptoEnv::CryptoEnv() {
    _crypto_service = CryptoService::Ptr(new emscriptenimpl::CryptoService());
}

CryptoService::Ptr emscriptenimpl::CryptoEnv::getCryptoService() {
    return _crypto_service;
}
