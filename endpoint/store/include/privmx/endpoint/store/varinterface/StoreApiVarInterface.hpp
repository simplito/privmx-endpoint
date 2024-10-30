#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/store/StoreVarDeserializer.hpp"
#include "privmx/endpoint/store/StoreVarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class StoreApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        CreateStore = 1,
        UpdateStore = 2,
        DeleteStore = 3,
        GetStore = 4,
        ListStores = 5,
        CreateFile = 6,
        UpdateFile = 7,
        UpdateFileMeta = 8,
        WriteToFile = 9,
        DeleteFile = 10,
        GetFile = 11,
        ListFiles = 12,
        OpenFile = 13,
        ReadFromFile = 14,
        SeekInFile = 15,
        CloseFile = 16,
        SubscribeForStoreEvents = 17,
        UnsubscribeFromStoreEvents = 18,
        SubscribeForFileEvents = 19,
        UnsubscribeFromFileEvents = 20
    };

    StoreApiVarInterface(core::Connection connection, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createStore(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateStore(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteStore(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getStore(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listStores(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateFileMeta(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var writeToFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listFiles(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var openFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var readFromFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var seekInFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var closeFile(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForStoreEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromStoreEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForFileEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromFileEvents(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    StoreApi getApi() const { return _storeApi; }

private:
    static std::map<METHOD, Poco::Dynamic::Var (StoreApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    StoreApi _storeApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace store
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STORE_STOREAPIVARINTERFACE_HPP_
