#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/inbox/InboxApi.hpp"
#include "privmx/endpoint/inbox/InboxVarDeserializer.hpp"
#include "privmx/endpoint/inbox/InboxVarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

class InboxApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        CreateInbox = 1,
        UpdateInbox = 2,
        GetInbox = 3,
        ListInboxes = 4,
        GetInboxPublicView = 5,
        DeleteInbox = 6,
        PrepareEntry = 7,
        SendEntry = 8,
        ReadEntry = 9,
        ListEntries = 10,
        DeleteEntry = 11,
        CreateFileHandle = 12,
        WriteToFile = 13,
        OpenFile = 14,
        ReadFromFile = 15,
        SeekInFile = 16,
        CloseFile = 17,
        SubscribeForInboxEvents = 18,
        UnsubscribeFromInboxEvents = 19,
        SubscribeForEntryEvents = 20,
        UnsubscribeFromEntryEvents = 21
    };

    InboxApiVarInterface(core::Connection connection, thread::ThreadApi threadApi, store::StoreApi storeApi, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _threadApi(std::move(threadApi)), _storeApi(std::move(storeApi)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createInbox(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateInbox(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getInbox(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listInboxes(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getInboxPublicView(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteInbox(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var prepareEntry(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var sendEntry(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var readEntry(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listEntries(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteEntry(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createFileHandle(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var writeToFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var openFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var readFromFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var seekInFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var closeFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForInboxEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromInboxEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForEntryEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromEntryEvents(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

private:
    static std::map<METHOD, Poco::Dynamic::Var (InboxApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    thread::ThreadApi _threadApi;
    store::StoreApi _storeApi;
    InboxApi _inboxApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace inbox
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_INBOX_INBOXAPIVARINTERFACE_HPP_
