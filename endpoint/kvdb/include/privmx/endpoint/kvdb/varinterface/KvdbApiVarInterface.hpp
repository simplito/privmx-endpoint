/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPIVARINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPIVARINTERFACE_HPP_

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/thread/KvdbApi.hpp"
#include "privmx/endpoint/thread/KvdbVarDeserializer.hpp"
#include "privmx/endpoint/thread/KvdbVarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class KvdbApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        CreateKvdb = 1,
        UpdateKvdb = 2,
        DeleteKvdb = 3,
        GetKvdb = 4,
        ListKvdbs = 5,
        GetValue = 6,
        ListValues = 7,
        SendValue = 8,
        DeleteValue = 9,
        UpdateValue = 10,
        SubscribeForKvdbEvents = 11,
        UnsubscribeFromKvdbEvents = 12,
        SubscribeForValueEvents = 13,
        UnsubscribeFromValueEvents = 14
    };

    KvdbApiVarInterface(core::Connection connection, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createKvdb(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateKvdb(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteKvdb(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getKvdb(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listKvdbs(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getValue(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listValues(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var sendValue(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteValue(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateValue(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForKvdbEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromKvdbEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForValueEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromValueEvents(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    KvdbApi getApi() const { return _threadApi; }

private:
    static std::map<METHOD, Poco::Dynamic::Var (KvdbApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    KvdbApi _threadApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace thread
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPIVARINTERFACE_HPP_
