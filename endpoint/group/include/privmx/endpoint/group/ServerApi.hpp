/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_SERVER_API_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_SERVER_API_HPP_

#include <string>
#include <Poco/Dynamic/Var.h>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include "privmx/endpoint/group/ServerTypes.hpp"

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
    T request(const std::string& method, Poco::JSON::Object::Ptr params); //only typed object
    Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params); //Var

    privfs::RpcGateway::Ptr _gateway;
};

} // group
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_SERVER_API_HPP_
