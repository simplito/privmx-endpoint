#ifndef _PRIVMXLIB_ENDPOINT_GROUP_MAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_MAPPER_HPP_

#include "privmx/endpoint/group/Events.hpp"
#include "privmx/endpoint/group/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace group {

class Mapper {
public:
    static GroupDeletedEventData mapToGroupDeletedEventData(const server::GroupDeletedEventData& data);
    static GroupChangedEventData mapToGroupChangedEventData(const server::GroupChangedEventData& data);
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_MAPPER_HPP_
