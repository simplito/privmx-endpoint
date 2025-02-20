/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADVARSERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADVARSERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarSerializer.hpp>
#include <string>

#include "privmx/endpoint/thread/Types.hpp"
#include "privmx/endpoint/thread/Events.hpp"
#include "privmx/endpoint/thread/ThreadValidator.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::Thread>(const thread::Thread& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<thread::Thread>>(const core::PagingList<thread::Thread>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ServerMessageInfo>(const thread::ServerMessageInfo& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::Message>(const thread::Message& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<core::PagingList<thread::Message>>(const core::PagingList<thread::Message>& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadCreatedEvent>(const thread::ThreadCreatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadUpdatedEvent>(const thread::ThreadUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadDeletedEventData>(const thread::ThreadDeletedEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadDeletedEvent>(const thread::ThreadDeletedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadStatsEventData>(const thread::ThreadStatsEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadStatsChangedEvent>(const thread::ThreadStatsChangedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadNewMessageEvent>(const thread::ThreadNewMessageEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadMessageUpdatedEvent>(const thread::ThreadMessageUpdatedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadDeletedMessageEventData>(const thread::ThreadDeletedMessageEventData& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadMessageDeletedEvent>(const thread::ThreadMessageDeletedEvent& val);

template<>
Poco::Dynamic::Var VarSerializer::serialize<thread::ThreadCustomEvent>(const thread::ThreadCustomEvent& val);



}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_THREAD_THREADVARSERIALIZER_HPP_
