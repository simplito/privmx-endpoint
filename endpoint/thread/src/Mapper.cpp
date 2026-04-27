/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/Mapper.hpp"

using namespace privmx::endpoint::thread;

ThreadDeletedEventData Mapper::mapToThreadDeletedEventData(const server::ThreadDeletedEventData_c_struct& data) {
    return {.threadId = data.threadId};
}

ThreadDeletedMessageEventData Mapper::mapToThreadDeletedMessageEventData(const server::ThreadDeletedMessageEventData_c_struct& data) {
    return {.threadId = data.threadId, .messageId = data.messageId};
}

ThreadStatsEventData Mapper::mapToThreadStatsEventData(const server::ThreadStatsEventData_c_struct& data) {
    return {.threadId = data.threadId, .lastMsgDate = data.lastMsgDate, .messagesCount = data.messages};
}
