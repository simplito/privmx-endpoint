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

    server::ThreadCreateResult threadCreate(server::ThreadCreateModel model);
    void threadUpdate(server::ThreadUpdateModel model);
    void threadDelete(server::ThreadDeleteModel model);
    server::ThreadGetResult threadGet(server::ThreadGetModel model);
    server::ThreadListResult threadList(server::ThreadListModel model);
    server::ThreadMessageSendResult threadMessageSend(server::ThreadMessageSendModel model);
    void threadMessageDelete(server::ThreadMessageDeleteModel model);
    server::ThreadMessageGetResult threadMessageGet(server::ThreadMessageGetModel model);
    server::ThreadMessagesGetResult threadMessagesGet(server::ThreadMessagesGetModel model);
    void threadMessageUpdate(server::ThreadMessageUpdateModel model);
private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params); //only typed object
    Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params); //Var

    privfs::RpcGateway::Ptr _gateway;
};

} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_SERVER_API_HPP_
