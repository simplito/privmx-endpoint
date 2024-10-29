#include "privmx/endpoint/thread/Mapper.hpp"

using namespace privmx::endpoint::thread;

ThreadDeletedEventData Mapper::mapToThreadDeletedEventData(const server::ThreadDeletedEventData& data) {
    return {.threadId = data.threadId()};
}

ThreadDeletedMessageEventData Mapper::mapToThreadDeletedMessageEventData(const server::ThreadDeletedMessageEventData& data) {
    return {.threadId = data.threadId(), .messageId = data.messageId()};
}

ThreadStatsEventData Mapper::mapToThreadStatsEventData(const server::ThreadStatsEventData& data) {
    return {.threadId = data.threadId(), .lastMsgDate = data.lastMsgDate(), .messagesCount = data.messages()};
}
