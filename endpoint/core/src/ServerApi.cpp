/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/ServerApi.hpp"
#include <privmx/utils/JsonHelper.hpp>

using namespace privmx::endpoint::core;

ServerApi::ServerApi(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

server::ContextGetResult_c_struct ServerApi::contextGet(server::ContextGetModel_c_struct model) {
    return request<server::ContextGetResult_c_struct>("contextGet", model.toJSON());
}

server::ContextListResult_c_struct ServerApi::contextList(server::ListModel_c_struct model) {
    return request<server::ContextListResult_c_struct>("contextList", model.toJSON());
}

server::ContextListUsersResult_c_struct ServerApi::contextListUsers(server::ContextListUsersModel_c_struct model) {
    return request<server::ContextListUsersResult_c_struct>("contextListUsers", model.toJSON());
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    auto result = _gateway->request("context." + method, params);
    return T::fromJSON(result);
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return _gateway->request("context." + method, params);
}
