#include <emscripten/emscripten.h>
#include <emscripten/val.h>

#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/ecc/BN.hpp>
#include <privmx/crypto/emscripten/ecc/BNImpl.hpp>
#include <privmx/crypto/emscripten/Bindings.hpp>
#include <privmx/crypto/CryptoConfig.hpp>


using namespace privmx::crypto::emscriptenimpl;
using namespace std;


#ifdef PRIVMX_DEFAULT_CRYPTO_EMSCRIPTEN
privmx::crypto::BNImpl::Ptr privmx::crypto::BNImpl::fromBuffer(const string& data) {
    return privmx::crypto::emscriptenimpl::BNImpl::fromBuffer(data);
}

privmx::crypto::BNImpl::Ptr privmx::crypto::BNImpl::getDefault() {
    return privmx::crypto::emscriptenimpl::BNImpl::getDefault();
}
#endif

BNImpl::Ptr BNImpl::fromBuffer(const string& data) {
    return new BNImpl(data);
}

BNImpl::Ptr BNImpl::getDefault() {
    return new BNImpl();
}

BNImpl::BNImpl(const BNImpl& obj) : _bn(obj._bn) {}

BNImpl::BNImpl(BNImpl&& obj) : _bn(move(obj._bn)) {}

BNImpl::BNImpl(const std::string& bn) : _bn(bn) {}

BNImpl& BNImpl::operator=(const BNImpl& obj) {
    _bn = obj._bn;
    return *this;
}

BNImpl& BNImpl::operator=(BNImpl&& obj) {
    _bn = move(obj._bn);
    return *this;
}

string BNImpl::toBuffer() const {
    return _bn;
}

std::size_t BNImpl::getBitsLength() const {
    validate();
    emscripten::val name { emscripten::val::u8string("bn_getBitsLength") };
    emscripten::val params { emscripten::val::object() };
    params.set("bn", emscripten::typed_memory_view(_bn.size(), _bn.data())); 

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on sign");
    }

    return result["buff"].as<int>();
}

BNImpl::Ptr BNImpl::umod(const BNImpl::Ptr bn) const {
    validate();
    emscripten::val name { emscripten::val::u8string("bn_umod") };
    emscripten::val params { emscripten::val::object() };
    params.set("bn", emscripten::typed_memory_view(_bn.size(), _bn.data()));
    auto tmp2 = bn->toBuffer();
    params.set("bn2", emscripten::typed_memory_view(tmp2.size(), tmp2.data())); 

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on sign");
    }

    return new BNImpl(result["buff"].as<std::string>());
}

bool BNImpl::eq(const BNImpl::Ptr bn) const {
    validate();
    emscripten::val name { emscripten::val::u8string("bn_eq") };
    emscripten::val params { emscripten::val::object() };
    params.set("bn", emscripten::typed_memory_view(_bn.size(), _bn.data())); 
    auto tmp2 = bn->toBuffer();
    params.set("bn2", emscripten::typed_memory_view(bn->toBuffer().size(), bn->toBuffer().data())); 

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on sign");
    }

    return result["buff"].as<bool>();
}

void BNImpl::validate() const {
    if (isEmpty()) {
        throw EmptyBNException();
    }
}
