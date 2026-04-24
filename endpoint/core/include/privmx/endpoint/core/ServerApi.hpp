/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_SERVER_API_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_SERVER_API_HPP_

#include <string>
#include <Poco/Dynamic/Var.h>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include "privmx/endpoint/core/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class ServerApi {
public:
    using Ptr = Poco::SharedPtr<ServerApi>;

    ServerApi(privmx::privfs::RpcGateway::Ptr gateway);

    server::ContextGetResult_c_struct contextGet(server::ContextGetModel_c_struct model);
    server::ContextListResult_c_struct contextList(server::ListModel_c_struct model);
    server::ContextListUsersResult_c_struct contextListUsers(server::ContextListUsersModel_c_struct model);

private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params);
    Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params);

    privfs::RpcGateway::Ptr _gateway;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SERVER_API_HPP_
