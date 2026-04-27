/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_SERVER_API_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_SERVER_API_HPP_

#include <string>
#include <Poco/Dynamic/Var.h>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include "privmx/endpoint/thread/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class ServerApi {
public:
    using Ptr = Poco::SharedPtr<ServerApi>;

    ServerApi(privmx::privfs::RpcGateway::Ptr gateway);

    server::ThreadCreateResult_c_struct threadCreate(server::ThreadCreateModel_c_struct model);
    void threadUpdate(server::ThreadUpdateModel_c_struct model);
    void threadDelete(server::ThreadDeleteModel_c_struct model);
    server::ThreadGetResult_c_struct threadGet(server::ThreadGetModel_c_struct model);
    server::ThreadListResult_c_struct threadList(server::ThreadListModel_c_struct model);
    server::ThreadMessageSendResult_c_struct threadMessageSend(server::ThreadMessageSendModel_c_struct model);
    void threadMessageDelete(server::ThreadMessageDeleteModel_c_struct model);
    server::ThreadMessageGetResult_c_struct threadMessageGet(server::ThreadMessageGetModel_c_struct model);
    server::ThreadMessagesGetResult_c_struct threadMessagesGet(server::ThreadMessagesGetModel_c_struct model);
    void threadMessageUpdate(server::ThreadMessageUpdateModel_c_struct model);
private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params);
    Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params); //Var

    privfs::RpcGateway::Ptr _gateway;
};

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_SERVER_API_HPP_
