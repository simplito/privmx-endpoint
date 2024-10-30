#include "privmx/endpoint/thread/ServerApi.hpp"

using namespace privmx::endpoint::thread;
using namespace privmx::endpoint;

ServerApi::ServerApi(privmx::privfs::RpcGateway::Ptr gateway) : _gateway(gateway) {}

server::ThreadCreateResult ServerApi::threadCreate(server::ThreadCreateModel model) {
    return request<server::ThreadCreateResult>("threadCreate", model);
}

void ServerApi::threadUpdate(server::ThreadUpdateModel model) {
    request("threadUpdate", model);
}

void ServerApi::threadDelete(server::ThreadDeleteModel model) {
    request("threadDelete", model);
}

server::ThreadGetResult ServerApi::threadGet(server::ThreadGetModel model) {
    return request<server::ThreadGetResult>("threadGet", model);
}

server::ThreadListResult ServerApi::threadList(server::ThreadListModel model) {
    return request<server::ThreadListResult>("threadList", model);
}

server::ThreadMessageSendResult ServerApi::threadMessageSend(server::ThreadMessageSendModel model) {
    return request<server::ThreadMessageSendResult>("threadMessageSend", model);
}

void ServerApi::threadMessageDelete(server::ThreadMessageDeleteModel model) {
    request("threadMessageDelete", model);
}

server::ThreadMessageGetResult ServerApi::threadMessageGet(server::ThreadMessageGetModel model) {
    return request<server::ThreadMessageGetResult>("threadMessageGet", model);
}

server::ThreadMessagesGetResult ServerApi::threadMessagesGet(server::ThreadMessagesGetModel model) {
    return request<server::ThreadMessagesGetResult>("threadMessagesGet", model);
}

void ServerApi::threadMessageUpdate(server::ThreadMessageUpdateModel model) {
    request("threadMessageUpdate", model);
}

template<class T> T ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {  //only typed object
    return privmx::utils::TypedObjectFactory::createObjectFromVar<T>(_gateway->request("thread." + method, params));
}

Poco::Dynamic::Var ServerApi::request(const std::string& method, Poco::JSON::Object::Ptr params) {  //var
    return _gateway->request("thread." + method, params);
}