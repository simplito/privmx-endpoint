#ifndef _PRIVMXLIB_ENDPOINT_CORE_VARPINSTOREINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_VARPINSTOREINTERFACE_HPP_

#include "privmx/endpoint/core/PinStoreInterface.hpp"
#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"
#include <functional>
#include <string>

namespace privmx {
namespace endpoint {
namespace core {

// A PinStoreInterface over two Var callbacks: load([key]) -> binary or null, save([key, blob, expected]) -> bool.
class VarPinStoreInterface : public virtual PinStoreInterface {
public:
    using Callback = std::function<Poco::Dynamic::Var(const Poco::Dynamic::Var&)>;

    VarPinStoreInterface(
        const Callback& load,
        const Callback& save,
        const core::VarDeserializer& deserializer,
        const core::VarSerializer& serializer
    )
        : _load(load), _save(save), _deserializer(deserializer), _serializer(serializer) {}

    Buffer load(const std::string& key) override {
        Poco::JSON::Array::Ptr args = new Poco::JSON::Array();
        args->add(_serializer.serialize(key));
        const Poco::Dynamic::Var result = _load(args);
        return result.isEmpty() ? Buffer() : _deserializer.deserialize<Buffer>(result, "blob");
    }

    bool save(const std::string& key, const Buffer& blob, const Buffer& expected) override {
        Poco::JSON::Array::Ptr args = new Poco::JSON::Array();
        args->add(_serializer.serialize(key));
        args->add(_serializer.serialize(blob));
        args->add(_serializer.serialize(expected));
        return _deserializer.deserialize<bool>(_save(args), "saved");
    }

private:
    Callback _load;
    Callback _save;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_VARPINSTOREINTERFACE_HPP_
