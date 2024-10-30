#ifndef _PRIVMXLIB_CLIENT_CLIENTNOTIFICATIONQUEUE_HPP_
#define _PRIVMXLIB_CLIENT_CLIENTNOTIFICATIONQUEUE_HPP_

#include <string>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>
#include <Poco/NotificationQueue.h>
#include <Poco/SharedPtr.h>

namespace privmx {
namespace client {

class ClientNotificationQueue
{
public:
    using Ptr = Poco::SharedPtr<ClientNotificationQueue>;

    ClientNotificationQueue(int cid, Poco::NotificationQueue& notification_queue);
    void enqueue(const std::string& type, const Poco::Dynamic::Var& data = Poco::Dynamic::Var());
    Poco::Dynamic::Var waitDequeue();

private:
    const int _cid;
    Poco::NotificationQueue& _notification_queue;
};

} // client
} // privmx

#endif // _PRIVMXLIB_CLIENT_CLIENTNOTIFICATIONQUEUE_HPP_
