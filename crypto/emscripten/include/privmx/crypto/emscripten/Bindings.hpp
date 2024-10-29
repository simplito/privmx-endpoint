#ifndef _PRIVMXLIB_CRYPTO_EMSCRIPTEN_BINDINGS_HPP_
#define _PRIVMXLIB_CRYPTO_EMSCRIPTEN_BINDINGS_HPP_

#include <emscripten.h>
#include <emscripten/val.h>
#include <emscripten/bind.h>

#include <privmx/crypto/CryptoException.hpp>

namespace privmx {
namespace crypto {
namespace emscriptenimpl {

using namespace emscripten;


class Bindings {
    public:
    static emscripten::val callJSRawSync(emscripten::val& name, emscripten::val& params);
    static void printErrorInJS(std::string& msg);

    template <typename T>
    static T callJSSync(emscripten::val& name, emscripten::val& params) {
        emscripten::val result = callJSRawSync(name, params);
        int status = result["status"].as<int>();
        if (status < 0) {
            auto errorString = result["error"].as<std::string>();
            printErrorInJS(errorString);
            throw CryptoException("Driver context error");
        }
        return result["buff"].as<T>();
    }
};

} // emscriptenimpl
} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_EMSCRIPTEN_BINDINGS_HPP_
