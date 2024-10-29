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
