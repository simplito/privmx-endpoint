/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_EVENTBUILDER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EVENTBUILDER_HPP_

#include <memory>
#include <string>
#include <vector>

#include "privmx/utils/Utils.hpp"
#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/Events.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class EventBuilder {
public:
    template<typename T, typename D>
    static std::shared_ptr<T> buildEvent(const std::string& channel, const D& data, const NotificationEvent& notification) {
        std::shared_ptr<T> event = std::make_shared<T>();
        event->channel = channel;
        event->data = data;
        event->subscriptions = notification.subscriptions;
        event->timestamp = notification.timestamp;
        return event;
    }
    template<typename T>
    static std::shared_ptr<T> buildLibEvent() {
        std::shared_ptr<T> event = std::make_shared<T>();
        event->timestamp = utils::Utils::getNowTimestamp();
        return event;
    }
};


}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_CORE_EVENTBUILDER_HPP_
