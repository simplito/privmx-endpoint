#include <emscripten/emscripten.h>
#include <emscripten/val.h>

#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/ecc/Point.hpp>
#include <privmx/crypto/emscripten/ecc/PointImpl.hpp>
#include <privmx/crypto/emscripten/ecc/BNImpl.hpp>
#include <privmx/crypto/emscripten/Bindings.hpp>
#include <privmx/crypto/CryptoConfig.hpp>


using namespace privmx::crypto::emscriptenimpl;
using namespace std;


#ifdef PRIVMX_DEFAULT_CRYPTO_EMSCRIPTEN
privmx::crypto::PointImpl::Ptr privmx::crypto::PointImpl::fromBuffer(const string& data) {
    return privmx::crypto::emscriptenimpl::PointImpl::fromBuffer(data);
}

privmx::crypto::PointImpl::Ptr privmx::crypto::PointImpl::getDefault() {
    return privmx::crypto::emscriptenimpl::PointImpl::getDefault();
}
#endif

PointImpl::Ptr PointImpl::fromBuffer(const string& data) {
    return new PointImpl(data);
}

PointImpl::Ptr PointImpl::getDefault() {
    return new PointImpl();
}

PointImpl::PointImpl(const PointImpl& obj) : _point(obj._point) {}

PointImpl::PointImpl(PointImpl&& obj) : _point(move(obj._point)) {}

PointImpl::PointImpl(const std::string& point) : _point(point) {}

PointImpl& PointImpl::operator=(const PointImpl& obj) {
    _point = obj._point;
    return *this;
}

PointImpl& PointImpl::operator=(PointImpl&& obj) {
    _point = move(obj._point);
    return *this;
}

string PointImpl::encode(bool compact) const {
    validate();
    emscripten::val name { emscripten::val::u8string("point_encode") };
    emscripten::val params { emscripten::val::object() };
    params.set("point", emscripten::typed_memory_view(_point.size(), _point.data()));
    params.set("compact", compact);

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on point_encode");
    }

    return result["buff"].as<std::string>();
}

PointImpl::Ptr PointImpl::mul(const BNImpl::Ptr bn) const {
    validate();
    emscripten::val name { emscripten::val::u8string("point_mul") };
    emscripten::val params { emscripten::val::object() };
    params.set("point", emscripten::typed_memory_view(_point.size(), _point.data())); 
    params.set("bn", emscripten::typed_memory_view(bn->toBuffer().size(), bn->toBuffer().data())); 

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on point_mul");
    }

    return new PointImpl(result["buff"].as<std::string>());
}

PointImpl::Ptr PointImpl::add(const PointImpl::Ptr point) const {
    validate();
    emscripten::val name { emscripten::val::u8string("point_add") };
    emscripten::val params { emscripten::val::object() };
    params.set("point", emscripten::typed_memory_view(_point.size(), _point.data())); 
    params.set("point2", emscripten::typed_memory_view(point.cast<PointImpl>()->_point.size(), point.cast<PointImpl>()->_point.data())); 

    emscripten::val result = Bindings::callJSRawSync(name, params);
    int status = result["status"].as<int>();
    if (status < 0) {
        auto errorString = result["error"].as<std::string>();
        Bindings::printErrorInJS(errorString);
        throw std::runtime_error("Error: on point_add");
    }

    return new PointImpl(result["buff"].as<std::string>());
    
}

void PointImpl::validate() const {
    if (_point.empty()) {
        throw EmptyPointException();
    }
}
