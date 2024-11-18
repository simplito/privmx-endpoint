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
#include <string>

#include "privmx/endpoint/core/BufferVarHolderImpl.hpp"
#include "privmx/endpoint/core/Exception.hpp"
#include "privmx/endpoint/core/TypeValidator.hpp"
#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class VarDeserializer {
public:
    template<typename T>
    T deserialize(const Poco::Dynamic::Var& value, const std::string& name) = delete;
    template<typename T>
    std::vector<T> deserializeVector(const Poco::Dynamic::Var& value, const std::string& name);
    template<typename T>
    std::optional<T> deserializeOptional(const Poco::Dynamic::Var& value, const std::string& name);
};

template<typename T>
inline std::vector<T> VarDeserializer::deserializeVector(const Poco::Dynamic::Var& val, const std::string& name) {
    std::vector<T> res;
    TypeValidator::validateArray(val, name);
    Poco::JSON::Array::Ptr arr = val.extract<Poco::JSON::Array::Ptr>();
    res.reserve(arr->size());
    for (const auto& item : *arr) {
        res.emplace_back(deserialize<T>(item, name + "[]"));
    }
    return res;
}

template<typename T>
inline std::optional<T> VarDeserializer::deserializeOptional(const Poco::Dynamic::Var& val, const std::string& name) {
    if (val.isEmpty()) {
        return std::nullopt;
    }
    return deserialize<T>(val.extract<T>(), name);
}

template<>
int64_t VarDeserializer::deserialize<int64_t>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
std::string VarDeserializer::deserialize<std::string>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
Buffer VarDeserializer::deserialize<Buffer>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
bool VarDeserializer::deserialize<bool>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
UserWithPubKey VarDeserializer::deserialize<UserWithPubKey>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
PagingQuery VarDeserializer::deserialize<PagingQuery>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
ContainerPolicyWithoutItem VarDeserializer::deserialize<ContainerPolicyWithoutItem>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
ContainerPolicy VarDeserializer::deserialize<ContainerPolicy>(const Poco::Dynamic::Var& val, const std::string& name);


}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_VARDESERIALIZER_HPP_
