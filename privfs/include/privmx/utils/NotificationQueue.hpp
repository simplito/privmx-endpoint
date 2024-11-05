/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_NOTIFICATIONQUEUE_HPP_
#define _PRIVMXLIB_UTILS_NOTIFICATIONQUEUE_HPP_

#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>
#include <Poco/Notification.h>
#include <Poco/NotificationQueue.h>
#include <Poco/SharedPtr.h>

namespace privmx {
namespace utils {

class NotificationQueue
{
public:
    using Ptr = Poco::SharedPtr<NotificationQueue>;

    void enqueue(const std::string& type, const Poco::Dynamic::Var& data = Poco::Dynamic::Var());
    Poco::Dynamic::Var waitDequeue();
    Poco::Dynamic::Var dequeueOne();

private:
    class Notification : public Poco::Notification
    {
    public:
        Notification(Poco::JSON::Object::Ptr data) : _data(data) {}
        Poco::JSON::Object::Ptr data() const {
            return _data;
        }

    private:
        Poco::JSON::Object::Ptr _data;
    };

    Poco::NotificationQueue _queue;
};

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_NOTIFICATIONQUEUE_HPP_
