/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/varinterface/KvdbApiVarInterface.hpp"

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

std::map<KvdbApiVarInterface::METHOD, Poco::Dynamic::Var (KvdbApiVarInterface::*)(const Poco::Dynamic::Var&)>
    KvdbApiVarInterface::methodMap = {{Create, &KvdbApiVarInterface::create},
                                        {CreateKvdb, &KvdbApiVarInterface::createKvdb},
                                        {UpdateKvdb, &KvdbApiVarInterface::updateKvdb},
                                        {DeleteKvdb, &KvdbApiVarInterface::deleteKvdb},
                                        {GetKvdb, &KvdbApiVarInterface::getKvdb},
                                        {ListKvdbs, &KvdbApiVarInterface::listKvdbs},
                                        {GetEntry, &KvdbApiVarInterface::getEntry},
                                        {ListEntriesKeys, &KvdbApiVarInterface::listEntriesKeys},
                                        {ListEntries, &KvdbApiVarInterface::listEntries},
                                        {SetEntry, &KvdbApiVarInterface::setEntry},
                                        {DeleteEntry, &KvdbApiVarInterface::deleteEntry},
                                        {DeleteEntries, &KvdbApiVarInterface::deleteEntries},
                                        {HasEntry, &KvdbApiVarInterface::hasEntry},
                                        {SubscribeFor, &KvdbApiVarInterface::subscribeFor},
                                        {UnsubscribeFrom, &KvdbApiVarInterface::unsubscribeFrom},
                                        {BuildSubscriptionQuery, &KvdbApiVarInterface::buildSubscriptionQuery},
                                        {BuildSubscriptionQueryForSelectedEntry, &KvdbApiVarInterface::buildSubscriptionQueryForSelectedEntry}};

Poco::Dynamic::Var KvdbApiVarInterface::create(const Poco::Dynamic::Var& args) {
    core::VarInterfaceUtil::validateAndExtractArray(args, 0);
    _kvdbApi = KvdbApi::create(_connection);
    return {};
}

Poco::Dynamic::Var KvdbApiVarInterface::createKvdb(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 6);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(5), "policies");
    auto result = _kvdbApi.createKvdb(contextId, users, managers, publicMeta, privateMeta, policies);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var KvdbApiVarInterface::updateKvdb(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 9);
    auto kvdbId = _deserializer.deserialize<std::string>(argsArr->get(0), "kvdbId");
    auto users = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(1), "users");
    auto managers = _deserializer.deserializeVector<core::UserWithPubKey>(argsArr->get(2), "managers");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "privateMeta");
    auto version = _deserializer.deserialize<int64_t>(argsArr->get(5), "version");
    auto force = _deserializer.deserialize<bool>(argsArr->get(6), "force");
    auto forceGenerateNewKey = _deserializer.deserialize<bool>(argsArr->get(7), "forceGenerateNewKey");
    auto policies = _deserializer.deserializeOptional<core::ContainerPolicy>(argsArr->get(8), "policies");
    _kvdbApi.updateKvdb(kvdbId, users, managers, publicMeta, privateMeta, version, force, forceGenerateNewKey, policies);
    return {};
}

Poco::Dynamic::Var KvdbApiVarInterface::deleteKvdb(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto kvdbId = _deserializer.deserialize<std::string>(argsArr->get(0), "kvdbId");
    _kvdbApi.deleteKvdb(kvdbId);
    return {};
}

Poco::Dynamic::Var KvdbApiVarInterface::getKvdb(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto kvdbId = _deserializer.deserialize<std::string>(argsArr->get(0), "kvdbId");
    auto result = _kvdbApi.getKvdb(kvdbId);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var KvdbApiVarInterface::listKvdbs(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto contextId = _deserializer.deserialize<std::string>(argsArr->get(0), "contextId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _kvdbApi.listKvdbs(contextId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var KvdbApiVarInterface::getEntry(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto kvdbId = _deserializer.deserialize<std::string>(argsArr->get(0), "kvdbId");
    auto key = _deserializer.deserialize<std::string>(argsArr->get(1), "key");
    auto result = _kvdbApi.getEntry(kvdbId, key);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var KvdbApiVarInterface::listEntriesKeys(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto kvdbId = _deserializer.deserialize<std::string>(argsArr->get(0), "kvdbId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _kvdbApi.listEntriesKeys(kvdbId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var KvdbApiVarInterface::listEntries(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto kvdbId = _deserializer.deserialize<std::string>(argsArr->get(0), "kvdbId");
    auto pagingQuery = _deserializer.deserialize<core::PagingQuery>(argsArr->get(1), "pagingQuery");
    auto result = _kvdbApi.listEntries(kvdbId, pagingQuery);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var KvdbApiVarInterface::setEntry(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 5, 6);
    auto kvdbId = _deserializer.deserialize<std::string>(argsArr->get(0), "kvdbId");
    auto key = _deserializer.deserialize<std::string>(argsArr->get(1), "key");
    auto publicMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(2), "publicMeta");
    auto privateMeta = _deserializer.deserialize<core::Buffer>(argsArr->get(3), "privateMeta");
    auto data = _deserializer.deserialize<core::Buffer>(argsArr->get(4), "data");
    int64_t version = 0;
    if(argsArr->size() >= 6) {
        version = _deserializer.deserialize<int64_t>(argsArr->get(5), "version");
    }
    _kvdbApi.setEntry(kvdbId, key, publicMeta, privateMeta, data, version);
    return {};
}

Poco::Dynamic::Var KvdbApiVarInterface::deleteEntry(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto kvdbId = _deserializer.deserialize<std::string>(argsArr->get(0), "kvdbId");
    auto key = _deserializer.deserialize<std::string>(argsArr->get(1), "key");
    _kvdbApi.deleteEntry(kvdbId, key);
    return {};
}


Poco::Dynamic::Var KvdbApiVarInterface::deleteEntries(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto kvdbId = _deserializer.deserialize<std::string>(argsArr->get(0), "kvdbId");
    auto keys = _deserializer.deserializeVector<std::string>(argsArr->get(1), "keys");
    auto result = _kvdbApi.deleteEntries(kvdbId, keys);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var KvdbApiVarInterface::hasEntry(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto kvdbId = _deserializer.deserialize<std::string>(argsArr->get(0), "kvdbId");
    auto key = _deserializer.deserialize<std::string>(argsArr->get(1), "key");
    auto result = _kvdbApi.hasEntry(kvdbId, key);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var KvdbApiVarInterface::subscribeFor(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionQueries = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionQueries");
    auto result = _kvdbApi.subscribeFor(subscriptionQueries);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var KvdbApiVarInterface::unsubscribeFrom(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
    auto subscriptionIds = _deserializer.deserializeVector<std::string>(argsArr->get(0), "subscriptionIds");
    _kvdbApi.unsubscribeFrom(subscriptionIds);
    return {};
}

Poco::Dynamic::Var KvdbApiVarInterface::buildSubscriptionQuery(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto eventType = _deserializer.deserialize<kvdb::EventType>(argsArr->get(0), "eventType");
    auto selectorType = _deserializer.deserialize<kvdb::EventSelectorType>(argsArr->get(1), "selectorType");
    auto selectorId = _deserializer.deserialize<std::string>(argsArr->get(2), "selectorId");
    auto result = _kvdbApi.buildSubscriptionQuery(eventType, selectorType, selectorId);
    return _serializer.serialize(result);
}
Poco::Dynamic::Var KvdbApiVarInterface::buildSubscriptionQueryForSelectedEntry(const Poco::Dynamic::Var& args) {
    auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
    auto eventType = _deserializer.deserialize<kvdb::EventType>(argsArr->get(0), "eventType");
    auto kvdbId = _deserializer.deserialize<std::string>(argsArr->get(1), "kvdbId");
    auto kvdbEntryKey = _deserializer.deserialize<std::string>(argsArr->get(2), "kvdbEntryKey");
    auto result = _kvdbApi.buildSubscriptionQueryForSelectedEntry(eventType, kvdbId, kvdbEntryKey);
    return _serializer.serialize(result);
}

Poco::Dynamic::Var KvdbApiVarInterface::exec(METHOD method, const Poco::Dynamic::Var& args) {
    auto it = methodMap.find(method);
    if (it == methodMap.end()) {
        throw core::InvalidMethodException();
    }
    return (*this.*(it->second))(args);
}
