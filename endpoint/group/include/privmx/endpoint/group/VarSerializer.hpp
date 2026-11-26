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
Poco::Dynamic::Var VarSerializer::serialize<group::EnvelopeAuthor>(const group::EnvelopeAuthor& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::EnvelopeSender>(const group::EnvelopeSender& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::EnvelopeAudience>(const group::EnvelopeAudience& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedEnvelope>(const group::DecryptedEnvelope& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupErrorDetails>(const group::GroupErrorDetails& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptResult>(const group::DecryptResult& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedOutsiderEnvelope>(
    const group::DecryptedOutsiderEnvelope& val
);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedAnonymousEnvelope>(
    const group::DecryptedAnonymousEnvelope& val
);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedSharedEnvelope>(const group::DecryptedSharedEnvelope& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupEpochRef>(const group::GroupEpochRef& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::EnvelopeHeader>(const group::EnvelopeHeader& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::PathSegment>(const group::PathSegment& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupResult>(const group::GroupResult& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupPublicKey>(const group::GroupPublicKey& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupRules>(const group::GroupRules& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupLogEntry>(const group::GroupLogEntry& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<group::GroupLogEntry>>(
    const core::PagingList<group::GroupLogEntry>& val
);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedFileInfo>(const group::DecryptedFileInfo& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SpaceGroupRecipient>(const group::SpaceGroupRecipient& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SpaceUserRecipient>(const group::SpaceUserRecipient& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SpaceState>(const group::SpaceState& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SpaceOrigin>(const group::SpaceOrigin& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::DecryptedSpaceEnvelope>(const group::DecryptedSpaceEnvelope& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SpaceDecryptResult>(const group::SpaceDecryptResult& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<group::SpaceState>>(
    const core::PagingList<group::SpaceState>& val
);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::CipherRange>(const group::CipherRange& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SequenceItemHeader>(const group::SequenceItemHeader& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SequenceAppendResult>(const group::SequenceAppendResult& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SequenceItem>(const group::SequenceItem& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::SequenceMarkInfo>(const group::SequenceMarkInfo& val);

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

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupCustomEventData>(const group::GroupCustomEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<group::GroupCustomEvent>(const group::GroupCustomEvent& val);

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_VARSERIALIZER_HPP_
