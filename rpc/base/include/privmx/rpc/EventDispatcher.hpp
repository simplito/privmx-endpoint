/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_RPC_EVENTDISPATCHER_HPP_
#define _PRIVMXLIB_RPC_EVENTDISPATCHER_HPP_

#include <string>
#include <Poco/JSON/Object.h>
#include <Poco/SharedPtr.h>

#include <privmx/utils/Types.hpp>

namespace privmx {
namespace rpc {

class EventDispatcher
{
public:
    using Ptr = Poco::SharedPtr<EventDispatcher>;
    int addEventListener(const std::string& type, std::function<void(Poco::JSON::Object::Ptr)> event_listener);
    void removeEventListener(const std::string& type, int listener_id);
    void dispatchEvent(Poco::JSON::Object::Ptr event);
    void clear();

private:
    int _current_id = 1;
    std::unordered_map<std::string, std::unordered_map<int, std::function<void(Poco::JSON::Object::Ptr)>>> _map;
    utils::Mutex _mutex;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_EVENTDISPATCHER_HPP_
