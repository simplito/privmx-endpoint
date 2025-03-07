/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_SERVERAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_SERVERAPI_HPP_

#include <string>
#include <Poco/Dynamic/Var.h>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/endpoint/thread/ServerApi.hpp>
#include "privmx/endpoint/store/ServerApi.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/inbox/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

class ServerApi : public thread::ServerApi, public store::ServerApi {
public:
    using Ptr = Poco::SharedPtr<ServerApi>;

    ServerApi(const privmx::privfs::RpcGateway::Ptr gateway);

    server::InboxCreateResult inboxCreate(server::InboxCreateModel model);

    void inboxUpdate(server::InboxUpdateModel model);

    server::InboxGetResult inboxGet(server::InboxGetModel model);

    server::InboxGetPublicViewResult inboxGetPublicView(server::InboxGetModel model);

    server::InboxListResult inboxList(server::InboxListModel model);

    void inboxSend(server::InboxSendModel model);

    void inboxDelete(server::InboxDeleteModel model);

    void inboxSendCustomEvent(server::InboxEmitCustomEventModel model);
private:
    template<typename T>
    T request(std::string method, Poco::JSON::Object::Ptr params); //only typed object
    Poco::Dynamic::Var request(std::string method, Poco::JSON::Object::Ptr params); //Var

    privfs::RpcGateway::Ptr _gateway;
};

} // inbox
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_SERVERAPI_HPP_
