/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/utils/JsonHelper.hpp>
#include "privmx/endpoint/store/RequestApi.hpp"

using namespace privmx::endpoint::store;

RequestApi::RequestApi(privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

server::CreateRequestResult_c_struct RequestApi::createRequest(const server::CreateRequestModel_c_struct& model) {
    return request<server::CreateRequestResult_c_struct>("createRequest", model.toJSON());
}

void RequestApi::sendChunk(const server::ChunkModel_c_struct& model) {
    requestVoid("sendChunk", model.toJSON());
}

void RequestApi::commitFile(const server::CommitFileModel_c_struct& model) {
    requestVoid("commitFile", model.toJSON());
}

template<class T> T RequestApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {
    return T::fromJSON(_gateway->request("request." + method, params));
}

void RequestApi::requestVoid(const std::string& method, Poco::JSON::Object::Ptr params) {
    _gateway->request("request." + method, params);
}
