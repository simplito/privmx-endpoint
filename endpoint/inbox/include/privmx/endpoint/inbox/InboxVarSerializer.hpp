/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXVARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXVARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarSerializer.hpp>
#include <string>

#include "privmx/endpoint/inbox/InboxApi.hpp"
#include "privmx/endpoint/inbox/Events.hpp"
#include "privmx/endpoint/inbox/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::FilesConfig>(const inbox::FilesConfig& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxPublicView>(const inbox::InboxPublicView& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::Inbox>(const inbox::Inbox& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<inbox::Inbox>>(const core::PagingList<inbox::Inbox>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxEntry>(const inbox::InboxEntry& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<inbox::InboxEntry>>(const core::PagingList<inbox::InboxEntry>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxCreatedEvent>(const inbox::InboxCreatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxUpdatedEvent>(const inbox::InboxUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxDeletedEventData>(const inbox::InboxDeletedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxDeletedEvent>(const inbox::InboxDeletedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxEntryCreatedEvent>(const inbox::InboxEntryCreatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxEntryDeletedEventData>(const inbox::InboxEntryDeletedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<inbox::InboxEntryDeletedEvent>(const inbox::InboxEntryDeletedEvent& val);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STORE_STOREVARSERIALIZER_HPP_
