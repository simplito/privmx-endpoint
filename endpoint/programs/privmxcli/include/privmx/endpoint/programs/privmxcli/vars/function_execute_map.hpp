#include <functional>
#include <string>
#include <unordered_map>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>

#include <privmx/endpoint/endpoint/EndpointApiJSON.hpp>
#include "privmx/endpoint/programs/privmxcli/vars/function_enum.hpp"

using namespace privmx::endpoint;

const std::unordered_map<func_enum, std::function<Poco::Dynamic::Var(privmx::endpoint::EndpointApiJSON* , const Poco::JSON::Array::Ptr&)>> functions_execute = {
    {waitEvent, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->waitEvent(args);
    }},
    {getEvent, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->getEvent(args);
    }},
    {platformConnect, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->platformConnect(args);
    }},
    {platformDisconnect, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->platformDisconnect(args);
    }},
    {contextList, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->contextList(args);
    }},
    {threadCreate, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->threadCreate(args);
    }},
    {threadGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->threadGet(args);
    }},
    {threadList, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->threadList(args);
    }},
    {threadMessageSend, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->threadMessageSend(args);
    }},
    {threadMessagesGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->threadMessagesGet(args);
    }},
    {storeList, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeList(args);
    }},
    {storeGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeGet(args);
    }},
    {storeCreate, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeCreate(args);
    }},
    {storeFileGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeFileGet(args);
    }},
    {storeFileList, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeFileList(args);
    }},
    {storeFileCreate, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeFileCreate(args);
    }},
    {storeFileUpdate, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeFileUpdate(args);
    }},
    {storeFileOpen, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeFileOpen(args);
    }},
    {storeFileRead, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeFileRead(args);
    }},
    {storeFileWrite, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeFileWrite(args);
    }},
    {storeFileSeek, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeFileSeek(args);
    }},
    {storeFileClose, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeFileClose(args);
    }},
    {storeFileDelete, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeFileDelete(args);
    }},
    {cryptoPrivKeyNew, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->cryptoPrivKeyNew(args);
    }},
    {cryptoPubKeyNew, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->cryptoPubKeyNew(args);
    }},
    {cryptoEncrypt, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->cryptoEncrypt(args);
    }},
    {cryptoDecrypt, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->cryptoDecrypt(args);
    }},
    {cryptoSign, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->cryptoSign(args);
    }},
    {setCertsPath, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->setCertsPath(args);
    }},
    {cryptoKeyConvertPEMToWIF, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->cryptoKeyConvertPEMToWIF(args);
    }},
    {backendRequest, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->backendRequest(args);
    }},
    {threadDelete, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->threadDelete(args);
    }},
    {threadMessageDelete, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->threadMessageDelete(args);
    }},
    {threadMessageGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->threadMessageGet(args);
    }},
    {storeDelete, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeDelete(args);
    }},
    {messageGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->messageGet(args);
    }},
    {messagesGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->messagesGet(args);
    }},
    {messageSend, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->messageSend(args);
    }},
    {inboxCreate, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxCreate(args);
    }},
    {inboxUpdate, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxUpdate(args);
    }},
    {inboxGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxGet(args);
    }},
    {inboxList, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxList(args);
    }},
    {inboxPublicViewGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxPublicViewGet(args);
    }},
    {inboxCreateFileHandle, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxCreateFileHandle(args);
    }},
    {inboxSendPrepare, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxSendPrepare(args);
    }},
    {inboxSendFileDataChunk, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxSendFileDataChunk(args);
    }},
    {inboxSendCommit, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxSendCommit(args);
    }},
    {threadUpdate, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->threadUpdate(args);
    }},
    {storeUpdate, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->storeUpdate(args);
    }},
    {storeUpdate, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->cryptoPrivKeyNewPbkdf2(args);
    }},
    {subscribeToChannel, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->subscribeToChannel(args);
    }},
    {unsubscribeFromChannel, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->unsubscribeFromChannel(args);
    }},
    {fileGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->fileGet(args);
    }},
    {fileList, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->fileList(args);
    }},
    {fileOpen, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->fileOpen(args);
    }},
    {fileSeek, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->fileSeek(args);
    }},
    {fileRead, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->fileRead(args);
    }},
    {fileClose, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->fileClose(args);
    }},
    {inboxFileGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxFileGet(args);
    }},
    {inboxFileList, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxFileList(args);
    }},
    {inboxFileOpen, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxFileOpen(args);
    }},
    {inboxFileSeek, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxFileSeek(args);
    }},
    {inboxFileRead, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxFileRead(args);
    }},
    {inboxFileClose, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxFileClose(args);
    }},
    {inboxMessageGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxMessageGet(args);
    }},
    {inboxMessagesGet, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxMessagesGet(args);
    }},
    {messageDelete, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->messageDelete(args);
    }},
    {inboxDelete, [](privmx::endpoint::EndpointApiJSON* api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inboxDelete(args);
    }}
};