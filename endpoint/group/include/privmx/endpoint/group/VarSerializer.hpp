#ifndef _PRIVMXLIB_ENDPOINT_GROUP_VARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_VARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarSerializer.hpp>
#include <string>

#include "privmx/endpoint/group/Events.hpp"
#include "privmx/endpoint/group/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::Group>(const group::Group& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupSummary>(const group::GroupSummary& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<group::GroupSummary>>(
    const core::PagingList<group::GroupSummary>& val
);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupDeletedEventData>(const group::GroupDeletedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupChangedEventData>(const group::GroupChangedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupCreatedEvent>(const group::GroupCreatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupUpdatedEvent>(const group::GroupUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupDeletedEvent>(const group::GroupDeletedEvent& val);

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_VARSERIALIZER_HPP_
