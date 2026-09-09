#include "privmx/endpoint/group/Mapper.hpp"

using namespace privmx::endpoint::group;

GroupDeletedEventData Mapper::mapToGroupDeletedEventData(const server::GroupDeletedEventData& data) {
    return GroupDeletedEventData{.groupId = data.groupId, .contextId = data.contextId};
}

GroupChangedEventData Mapper::mapToGroupChangedEventData(const server::GroupChangedEventData& data) {
    return GroupChangedEventData{
        .groupId = data.groupId,
        .contextId = data.contextId,
        .version = data.version,
        .rosterVersion = data.rosterVersion,
        .keyVersion = data.keyVersion,
        .changeKind = data.changeKind
    };
}
