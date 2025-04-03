/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_STOREAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_STOREAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/store/StoreApi.hpp"
#include "privmx/endpoint/store/StoreVarDeserializer.hpp"
#include "privmx/endpoint/store/StoreVarSerializer.hpp"
#include "privmx/endpoint/store/c_api.h"

namespace privmx {
namespace endpoint {
namespace store {

class StoreApiVarInterface {
public:
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

    Poco::Dynamic::Var exec(privmx_StoreApi_Method method, const Poco::Dynamic::Var& args);

    StoreApi getApi() const { return _storeApi; }

private:
    static std::map<privmx_StoreApi_Method, Poco::Dynamic::Var (StoreApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    StoreApi _storeApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace store
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_STORE_STOREAPIVARINTERFACE_HPP_
