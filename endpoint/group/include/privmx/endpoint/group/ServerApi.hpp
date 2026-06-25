#ifndef _PRIVMXLIB_ENDPOINT_GROUP_SERVER_API_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_SERVER_API_HPP_

#include "privmx/endpoint/group/ServerTypes.hpp"
#include <Poco/Dynamic/Var.h>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <string>

namespace privmx {
namespace endpoint {
namespace group {

class ServerApi {
public:
    using Ptr = Poco::SharedPtr<ServerApi>;

    ServerApi(privmx::privfs::RpcGateway::Ptr gateway);

    server::GroupCreateResult groupCreate(server::GroupCreateModel model);
    void groupUpdate(server::GroupUpdateModel model);
    void groupDelete(server::GroupDeleteModel model);
    server::GroupGetResult groupGet(server::GroupGetModel model);
    server::GroupListResult groupList(server::GroupListModel model);

private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params);
    Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params);

    privfs::RpcGateway::Ptr _gateway;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_SERVER_API_HPP_
