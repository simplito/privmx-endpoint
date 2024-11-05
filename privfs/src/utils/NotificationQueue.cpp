/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>
#include <Poco/AutoPtr.h>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>

#include <privmx/utils/NotificationQueue.hpp>

using namespace privmx;
using namespace privmx::utils;
using namespace std;
using namespace Poco::Dynamic;
using namespace Poco::JSON;

void NotificationQueue::enqueue(const string& type, const Var& data) {
    Object::Ptr notification = new Object();
    notification->set("data", data);
    notification->set("type", type);
    notification->set("__type", "Event");
    _queue.enqueueNotification(new Notification(notification));
}

Var NotificationQueue::waitDequeue() {
    Poco::AutoPtr<Poco::Notification> notification(_queue.waitDequeueNotification());
    return dynamic_cast<Notification*>(notification.get())->data();
}

Var NotificationQueue::dequeueOne() {
    Poco::AutoPtr<Poco::Notification> notification(_queue.dequeueNotification());
    auto ret {dynamic_cast<Notification*>(notification.get())};
    if (ret) {
        return ret->data();
    }
    else {
        return Poco::JSON::Object::Ptr();
    }
}
