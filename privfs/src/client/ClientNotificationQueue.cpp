/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/AutoPtr.h>
#include <Poco/Notification.h>

#include <privmx/client/ClientNotification.hpp>
#include <privmx/client/ClientNotificationQueue.hpp>

using namespace privmx;
using namespace privmx::client;
using namespace std;
using namespace Poco;
using namespace Poco::JSON;
using Poco::Dynamic::Var;

ClientNotificationQueue::ClientNotificationQueue(int cid, NotificationQueue& notification_queue)
        : _cid(cid), _notification_queue(notification_queue) {}

void ClientNotificationQueue::enqueue(const string& type, const Var& data) {
    Object::Ptr notification = new Object();
    if (!data.isEmpty()) {
        notification->set("data", data);
    }
    notification->set("type", type);
    notification->set("cid", _cid);
    _notification_queue.enqueueNotification(new ClientNotification(notification));
}

Var ClientNotificationQueue::waitDequeue() {
    AutoPtr<Notification> notification(_notification_queue.waitDequeueNotification());
    return dynamic_cast<ClientNotification*>(notification.get())->data();
}
