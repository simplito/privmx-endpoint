/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <functional>
#include <string>
#include <unordered_map>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>

#include "privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/EventQueueVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/BackendRequesterVarInterface.hpp"
#include "privmx/endpoint/crypto/varinterface/CryptoApiVarInterface.hpp"
#include "privmx/endpoint/thread/varinterface/ThreadApiVarInterface.hpp"
#include "privmx/endpoint/store/varinterface/StoreApiVarInterface.hpp"
#include "privmx/endpoint/inbox/varinterface/InboxApiVarInterface.hpp"
#include "privmx/endpoint/programs/privmxcli/vars/function_enum.hpp"


#include "privmx/endpoint/core/Config.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"
#include "privmx/endpoint/core/CoreException.hpp"

namespace privmx {
namespace endpoint {
namespace privmxcli {

struct ApiVar {
    ApiVar(
        privmx::endpoint::core::EventQueueVarInterface _event,
        privmx::endpoint::core::ConnectionVarInterface _connection,
        privmx::endpoint::core::BackendRequesterVarInterface _backendRequester,
        privmx::endpoint::crypto::CryptoApiVarInterface _crypto,
        privmx::endpoint::thread::ThreadApiVarInterface _thread,
        privmx::endpoint::store::StoreApiVarInterface _store,
        privmx::endpoint::inbox::InboxApiVarInterface _inbox

    ) : event(_event), connection(_connection), backendRequester(_backendRequester), crypto(_crypto), thread(_thread), store(_store), inbox(_inbox) {}
    privmx::endpoint::core::EventQueueVarInterface event;
    privmx::endpoint::core::ConnectionVarInterface connection;
    privmx::endpoint::core::BackendRequesterVarInterface backendRequester;
    privmx::endpoint::crypto::CryptoApiVarInterface crypto;
    privmx::endpoint::thread::ThreadApiVarInterface thread;
    privmx::endpoint::store::StoreApiVarInterface store;
    privmx::endpoint::inbox::InboxApiVarInterface inbox;
};


const std::unordered_map<func_enum, std::function<Poco::Dynamic::Var(std::shared_ptr<ApiVar> , const Poco::JSON::Array::Ptr&)>> functions_execute = {
    {config_setCertsPath, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        auto argsArr = privmx::endpoint::core::VarInterfaceUtil::validateAndExtractArray(args, 1);
        Poco::Dynamic::Var certsPath = argsArr->get(0);
        if (!certsPath.isString()) {
            throw privmx::endpoint::core::InvalidArgumentTypeException("certsPath | Expected string, value has type " + (std::string)(certsPath.type().name()));
        }
        privmx::endpoint::core::Config::setCertsPath(certsPath.convert<std::string>());
        return Poco::Dynamic::Var();
    }},
    {core_waitEvent, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->event.waitEvent(args);
    }},
    {core_getEvent, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->event.getEvent(args);
    }},
    {core_emitBreakEvent, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->event.emitBreakEvent(args);
    }},
    {core_connect, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->connection.connect(args);
    }},
    {core_connectPublic, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->connection.connectPublic(args);
    }},
    {core_disconnect, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->connection.disconnect(args);
    }},
    {core_getConnectionId, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->connection.getConnectionId(args);
    }},
    {core_listContexts, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->connection.listContexts(args);
    }},
    {core_backendRequest, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->backendRequester.backendRequest(args);
    }},
    {crypto_signData, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->crypto.signData(args);
    }},
    {crypto_verifySignature, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->crypto.verifySignature(args);
    }},
    {crypto_generatePrivateKey, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->crypto.generatePrivateKey(args);
    }},
    {crypto_derivePrivateKey, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->crypto.derivePrivateKey(args);
    }},
    {crypto_derivePublicKey, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->crypto.derivePublicKey(args);
    }},
    {crypto_generateKeySymmetric, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->crypto.generateKeySymmetric(args);
    }},
    {crypto_encryptDataSymmetric, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->crypto.encryptDataSymmetric(args);
    }},
    {crypto_decryptDataSymmetric, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->crypto.decryptDataSymmetric(args);
    }},
    {crypto_convertPEMKeytoWIFKey, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->crypto.convertPEMKeytoWIFKey(args);
    }},
    {thread_createThread, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.createThread(args);
    }},
    {thread_updateThread, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.updateThread(args);
    }},
    {thread_getThread, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.getThread(args);
    }},
    {thread_listThreads, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.listThreads(args);
    }},
    {thread_deleteThread, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.deleteThread(args);
    }},
    {thread_sendMessage, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.sendMessage(args);
    }},
    {thread_updateMessage, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.updateMessage(args);
    }},
    {thread_getMessage, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.getMessage(args);
    }},
    {thread_listMessages, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.listMessages(args);
    }},
    {thread_deleteMessage, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.deleteMessage(args);
    }},
    {thread_subscribeForThreadEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.subscribeForThreadEvents(args);
    }},
    {thread_unsubscribeFromThreadEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.unsubscribeFromThreadEvents(args);
    }},
    {thread_subscribeForMessageEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.subscribeForMessageEvents(args);
    }},
    {thread_unsubscribeFromMessageEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->thread.unsubscribeFromMessageEvents(args);
    }},
    {store_createStore, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.createStore(args);
    }},
    {store_updateStore, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.updateStore(args);
    }},
    {store_getStore, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.getStore(args);
    }},
    {store_listStores, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.listStores(args);
    }},
    {store_deleteStore, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.deleteStore(args);
    }},
    {store_createFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.createFile(args);
    }},
    {store_updateFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.updateFile(args);
    }},
    {store_updateFileMeta, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.updateFileMeta(args);
    }},
    {store_getFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.getFile(args);
    }},
    {store_listFiles, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.listFiles(args);
    }},
    {store_deleteFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.deleteFile(args);
    }},
    {store_openFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.openFile(args);
    }},
    {store_readFromFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.readFromFile(args);
    }},
    {store_writeToFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.writeToFile(args);
    }},
    {store_seekInFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.seekInFile(args);
    }},
    {store_closeFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.closeFile(args);
    }},
    {store_subscribeForStoreEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.subscribeForStoreEvents(args);
    }},
    {store_unsubscribeFromStoreEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.unsubscribeFromStoreEvents(args);
    }},
    {store_subscribeForFileEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.subscribeForFileEvents(args);
    }},
    {store_unsubscribeFromFileEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->store.unsubscribeFromFileEvents(args);
    }},
    {inbox_createInbox, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.createInbox(args);
    }},
    {inbox_updateInbox, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.updateInbox(args);
    }},
    {inbox_getInbox, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.getInbox(args);
    }},
    {inbox_listInboxes, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.listInboxes(args);
    }},
    {inbox_deleteInbox, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.deleteInbox(args);
    }},
    {inbox_getInboxPublicView, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.getInboxPublicView(args);
    }},
    {inbox_getInboxPublicView, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.deleteInbox(args);
    }},
    {inbox_prepareEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.prepareEntry(args);
    }},
    {inbox_sendEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.sendEntry(args);
    }},
    {inbox_readEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.readEntry(args);
    }},
    {inbox_listEntries, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.listEntries(args);
    }},
    {inbox_deleteEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.deleteEntry(args);
    }},
    {inbox_createFileHandle, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.createFileHandle(args);
    }},
    {inbox_writeToFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.writeToFile(args);
    }},
    {inbox_openFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.openFile(args);
    }},
    {inbox_readFromFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.readFromFile(args);
    }},
    {inbox_seekInFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.seekInFile(args);
    }},
    {inbox_closeFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.closeFile(args);
    }},

    {inbox_subscribeForInboxEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.subscribeForInboxEvents(args);
    }},
    {inbox_unsubscribeFromInboxEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.unsubscribeFromInboxEvents(args);
    }},
    {inbox_subscribeForEntryEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.subscribeForEntryEvents(args);
    }},
    {inbox_unsubscribeFromEntryEvents, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
        return api->inbox.unsubscribeFromEntryEvents(args);
    }},

    // {inboxCreateFileHandle, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxCreateFileHandle(args);
    // }},
    // {inboxSendPrepare, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxSendPrepare(args);
    // }},
    // {inboxSendFileDataChunk, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxSendFileDataChunk(args);
    // }},
    // {inboxSendCommit, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxSendCommit(args);
    // }},
    // {inboxFileGet, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxFileGet(args);
    // }},
    // {inboxFileList, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxFileList(args);
    // }},
    // {inboxFileOpen, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxFileOpen(args);
    // }},
    // {inboxFileSeek, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxFileSeek(args);
    // }},
    // {inboxFileRead, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxFileRead(args);
    // }},
    // {inboxFileClose, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxFileClose(args);
    // }},
    // {inboxMessageGet, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxMessageGet(args);
    // }},
    // {inboxMessagesGet, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
    //     return api->inboxMessagesGet(args);
    // }}
};

} // privmxcli
} // endpoint
} // privmx