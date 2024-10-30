

#include <emscripten.h>
#include <emscripten/val.h>
#include <emscripten/bind.h>

#include <privmx/crypto/emscripten/Bindings.hpp>

using namespace privmx::crypto::emscriptenimpl;
using namespace emscripten;

EM_JS(EM_VAL, print_error, (const char* msg), {
    console.error(UTF8ToString(msg));
});

EM_ASYNC_JS(EM_VAL, em_method_caller, (EM_VAL name_handle, EM_VAL val_handle), {
    let name = Emval.toValue(name_handle);
    let params = Emval.toValue(val_handle);
    let response = {};

    try {
        response = await em_crypto.methodCaller(name, params);
    } catch (error) {
        console.error("Error on em_crypto.methodCaller call from C for", name, params);
        let ret = { status: -1, buff: "", error: error.toString()};
        return Emval.toHandle(ret);
    }

    let ret = {status: 1, buff: response, error: ""};

    return Emval.toHandle(ret);
});

void Bindings::printErrorInJS(std::string& msg) {
    print_error(msg.c_str());
}

val Bindings::callJSRawSync(val& name, val& params) {
    return val::take_ownership(em_method_caller(name.as_handle(), params.as_handle()));
}
