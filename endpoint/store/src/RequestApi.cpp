/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/RequestApi.hpp"

using namespace privmx::endpoint::store;

RequestApi::RequestApi(privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

template<class T> T RequestApi::request(const std::string& method, const Poco::JSON::Object::Ptr& params) {  //only typed object
    return privmx::utils::TypedObjectFactory::createObjectFromVar<T>(_gateway->request("request." + method, params));
}

Poco::Dynamic::Var RequestApi::request(const std::string& method, const Poco::JSON::Object::Ptr& params) {  //var
    return _gateway->request(method, params);
}

server::CreateRequestResult RequestApi::createRequest(const server::CreateRequestModel& model) {
    return request<server::CreateRequestResult>("createRequest", model);
}

void RequestApi::sendChunk(const server::ChunkModel& model) {
    request("sendChunk", model);
}

void RequestApi::commitFile(const server::CommitFileModel& model) {
    request("commitFile", model);
}
