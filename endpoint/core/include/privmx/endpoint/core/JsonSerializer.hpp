#ifndef _PRIVMXLIB_ENDPOINT_CORE_JSONSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_JSONSERIALIZER_HPP_

#include <string>

#include "privmx/endpoint/core/BufferVarHolderImpl.hpp"
#include "privmx/endpoint/core/VarDeserializer.hpp"
#include "privmx/endpoint/core/VarSerializer.hpp"
#include "privmx/utils/Utils.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<typename T>
class JsonSerializer {
public:
    static std::string serialize(const T& val, bool pretty = false);
    static T deserialize(const std::string& val, bool pretty = false);
};

template<typename T>
inline std::string JsonSerializer<T>::serialize(const T& val, bool pretty) {
    return privmx::utils::Utils::stringifyVar(VarSerializer({}).serialize(val), pretty);
}

template<typename T>
inline T JsonSerializer<T>::deserialize(const std::string& val, bool pretty) {
    return VarDeserializer().deserialize<T>(privmx::utils::Utils::parseJson(val));
}

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_JSONSERIALIZER_HPP_
