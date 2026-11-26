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
group::GroupRoleChange VarDeserializer::deserialize<group::GroupRoleChange>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

template<>
group::GroupRulesUpdate VarDeserializer::deserialize<group::GroupRulesUpdate>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

template<>
group::EventType VarDeserializer::deserialize<group::EventType>(const Poco::Dynamic::Var& val, const std::string& name);

template<>
group::PathSegment VarDeserializer::deserialize<group::PathSegment>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

template<>
group::DecryptOptions VarDeserializer::deserialize<group::DecryptOptions>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

template<>
group::SpaceRecipient VarDeserializer::deserialize<group::SpaceRecipient>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

template<>
group::SpaceRecipientRef VarDeserializer::deserialize<group::SpaceRecipientRef>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

template<>
group::EnvelopeRecipient VarDeserializer::deserialize<group::EnvelopeRecipient>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

template<>
group::EncryptOptions VarDeserializer::deserialize<group::EncryptOptions>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

template<>
group::DecryptItem VarDeserializer::deserialize<group::DecryptItem>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

template<>
group::EventSelectorType VarDeserializer::deserialize<group::EventSelectorType>(
    const Poco::Dynamic::Var& val,
    const std::string& name
);

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_VARDESERIALIZER_HPP_
