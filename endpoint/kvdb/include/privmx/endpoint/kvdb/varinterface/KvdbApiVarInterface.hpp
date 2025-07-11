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

#include <privmx/endpoint/core/VarDeserializer.hpp>
#include "privmx/endpoint/kvdb/KvdbApi.hpp"
#include "privmx/endpoint/kvdb/KvdbVarSerializer.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

class KvdbApiVarInterface {
public:
    enum METHOD {
        Create = 0,
        CreateKvdb = 1,
        UpdateKvdb = 2,
        DeleteKvdb = 3,
        GetKvdb = 4,
        ListKvdbs = 5,
        GetEntry = 6,
        ListEntriesKeys = 7,
        ListEntries = 8,
        SetEntry = 9,
        DeleteEntry = 10,
        DeleteEntries = 11,
        SubscribeForKvdbEvents = 12,
        UnsubscribeFromKvdbEvents = 13,
        SubscribeForEntryEvents = 14,
        UnsubscribeFromEntryEvents = 15,
        HasEntry = 16,
    };

    KvdbApiVarInterface(core::Connection connection, const core::VarSerializer& serializer)
        : _connection(std::move(connection)), _serializer(serializer) {}

    Poco::Dynamic::Var create(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var createKvdb(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var updateKvdb(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteKvdb(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getKvdb(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listKvdbs(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var getEntry(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listEntriesKeys(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var listEntries(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var setEntry(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteEntry(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var deleteEntries(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForKvdbEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromKvdbEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var subscribeForEntryEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var unsubscribeFromEntryEvents(const Poco::Dynamic::Var& args);
    Poco::Dynamic::Var hasEntry(const Poco::Dynamic::Var& args);

    Poco::Dynamic::Var exec(METHOD method, const Poco::Dynamic::Var& args);

    KvdbApi getApi() const { return _kvdbApi; }

private:
    static std::map<METHOD, Poco::Dynamic::Var (KvdbApiVarInterface::*)(const Poco::Dynamic::Var&)> methodMap;

    core::Connection _connection;
    KvdbApi _kvdbApi;
    core::VarDeserializer _deserializer;
    core::VarSerializer _serializer;
};

}  // namespace kvdb
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_KVDB_KVDBAPIVARINTERFACE_HPP_
