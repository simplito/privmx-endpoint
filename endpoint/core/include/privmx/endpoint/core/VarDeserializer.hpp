/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_VARDESERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_VARDESERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <Pson/BinaryString.hpp>
#include <privmx/utils/Utils.hpp>
#include <optional>
#include <string>
#include <vector>

#include "privmx/endpoint/core/BufferVarHolderImpl.hpp"
#include "privmx/endpoint/core/Exception.hpp"
#include "privmx/endpoint/core/TypeValidator.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/CoreException.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class VarDeserializer {
public:
    template<typename T>
    T deserialize(const Poco::Dynamic::Var& value, const std::string& name);
    template<typename T>
    void deserialize(const Poco::Dynamic::Var& value, const std::string& name, T& out) = delete;
    template<typename T>
    void deserialize(const Poco::Dynamic::Var& value, const std::string& name, std::vector<T>& out);
    template<typename T>
    void deserialize(const Poco::Dynamic::Var& value, const std::string& name, std::optional<T>& out);
    template<typename T>
    void deserialize(const Poco::Dynamic::Var& value, const std::string& name, std::optional<std::vector<T>>& out);
    template<typename T>
    void deserialize(const Poco::Dynamic::Var& value, const std::string& name, std::shared_ptr<T>*& out);
};

template<typename T>
inline T VarDeserializer::deserialize(const Poco::Dynamic::Var& value, const std::string& name) {
    T tmp{};
    deserialize(value, name, tmp);
    return tmp;
}

template<typename T>
inline void VarDeserializer::deserialize(const Poco::Dynamic::Var& val, const std::string& name, std::vector<T>& out) {
    TypeValidator::validateArray(val, name);
    Poco::JSON::Array::Ptr arr = val.extract<Poco::JSON::Array::Ptr>();
    out.reserve(arr->size());
    for (const auto& item : *arr) {
        T elem{};
        deserialize(item, name + "[]", elem);
        out.emplace_back(std::move(elem));
    }
}

template<typename T>
inline void VarDeserializer::deserialize(const Poco::Dynamic::Var& val, const std::string& name, std::optional<T>& out) {
    if (val.isEmpty()) {
        out = std::nullopt;
        return;
    }
    T tmp{};
    deserialize(val, name, tmp);
    out = std::move(tmp);
}

template<typename T>
inline void VarDeserializer::deserialize(const Poco::Dynamic::Var& val, const std::string& name, std::optional<std::vector<T>>& out) {
    if (val.isEmpty()) {
        out = std::nullopt;
        return;
    }
    std::vector<T> tmp;
    deserialize(val, name, tmp);
    out = std::move(tmp);
}

template<typename T>
inline void VarDeserializer::deserialize(const Poco::Dynamic::Var& value, const std::string& name, std::shared_ptr<T>*& out) {
    if (value.isEmpty()) {
        throw InvalidArgumentTypeException(name + " | Expected pointer, value is empty");
    }
    if (!value.isInteger()) {
        throw InvalidArgumentTypeException(name + " | Expected pointer, value has type " + value.type().name());
    }
    out = reinterpret_cast<std::shared_ptr<T>*>(static_cast<uintptr_t>(value.convert<Poco::Int64>()));
}

template<>
void VarDeserializer::deserialize<int64_t>(const Poco::Dynamic::Var& val, const std::string& name, int64_t& out);

template<>
void VarDeserializer::deserialize<std::string>(const Poco::Dynamic::Var& val, const std::string& name, std::string& out);

template<>
void VarDeserializer::deserialize<Buffer>(const Poco::Dynamic::Var& val, const std::string& name, Buffer& out);

template<>
void VarDeserializer::deserialize<bool>(const Poco::Dynamic::Var& val, const std::string& name, bool& out);

template<>
void VarDeserializer::deserialize<Poco::JSON::Object::Ptr>(const Poco::Dynamic::Var& val, const std::string& name, Poco::JSON::Object::Ptr& out);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#include "privmx/endpoint/core/VarSerialization.hpp"

#endif  // _PRIVMXLIB_ENDPOINT_CORE_VARDESERIALIZER_HPP_
