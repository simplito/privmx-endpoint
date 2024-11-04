/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CLIENT_CLIENTNOTIFICATION_HPP_
#define _PRIVMXLIB_CLIENT_CLIENTNOTIFICATION_HPP_

#include <Poco/JSON/Object.h>
#include <Poco/Notification.h>

namespace privmx {
namespace client {

class ClientNotification : public Poco::Notification
{
public:
    ClientNotification(Poco::JSON::Object::Ptr data) : _data(data) {}
    Poco::JSON::Object::Ptr data() const {
        return _data;
    }

private:
    Poco::JSON::Object::Ptr _data;
};

} // client
} // privmx

#endif // _PRIVMXLIB_CLIENT_CLIENTNOTIFICATION_HPP_
