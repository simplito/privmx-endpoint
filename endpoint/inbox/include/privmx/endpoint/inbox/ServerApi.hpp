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

    server::InboxCreateResult_c_struct inboxCreate(server::InboxCreateModel_c_struct model);
    void inboxUpdate(server::InboxUpdateModel_c_struct model);
    server::InboxGetResult_c_struct inboxGet(server::InboxGetModel_c_struct model);
    server::InboxGetPublicViewResult_c_struct inboxGetPublicView(server::InboxGetModel_c_struct model);
    server::InboxListResult_c_struct inboxList(server::InboxListModel_c_struct model);
    void inboxSend(server::InboxSendModel_c_struct model);
    void inboxDelete(server::InboxDeleteModel_c_struct model);
private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params);
    Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params);

    privfs::RpcGateway::Ptr _gateway;
};

} // inbox
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_SERVERAPI_HPP_
