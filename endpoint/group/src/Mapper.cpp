#include "privmx/endpoint/group/Mapper.hpp"

using namespace privmx::endpoint::group;

GroupDeletedEventData Mapper::mapToGroupDeletedEventData(const server::GroupDeletedEventData& data) {
    return GroupDeletedEventData{.groupId = data.groupId, .contextId = data.contextId};
}
