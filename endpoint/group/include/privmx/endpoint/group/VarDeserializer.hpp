#ifndef _PRIVMXLIB_ENDPOINT_GROUP_VARDESERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_VARDESERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <string>

#include "privmx/endpoint/group/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
group::GroupMemberToAdd VarDeserializer::deserialize<group::GroupMemberToAdd>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

template<>
group::EventType VarDeserializer::deserialize<group::EventType>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
group::EventSelectorType VarDeserializer::deserialize<group::EventSelectorType>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_VARDESERIALIZER_HPP_
