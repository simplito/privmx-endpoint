/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>

#include "privmx/endpoint/core/EventBuilder.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"
#include "privmx/endpoint/core/Mapper.hpp"
#include "privmx/endpoint/core/UsersKeysResolver.hpp"
#include "privmx/endpoint/group/GroupApiImpl.hpp"
#include "privmx/endpoint/kvdb/KvdbApiImpl.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include "privmx/endpoint/kvdb/Mapper.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include <privmx/endpoint/core/ConvertedExceptions.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

KvdbApiImpl::KvdbApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const core::Connection& connection,
    const std::optional<group::GroupApi>& groupApi
)
    : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection), _gateway(gateway),
      _userPrivKey(userPrivKey), _keyProvider(keyProvider), _host(host), _eventMiddleware(eventMiddleware),
      _connection(connection), _serverApi(ServerApi(gateway)), _subscriber(gateway, KVDB_TYPE_FILTER_FLAG),
      _kvdbDataSchemaMapper(std::make_shared<KvdbDataSchemaMapper>(userPrivKey, connection)),
      _entryDataSchemaMapper(userPrivKey, connection) {
    if (groupApi.has_value()) {
        initGroupResolvers(group::GroupApiImpl::makeGroupResolvers(groupApi->getImpl()));
    }
    initModuleDataSchemaMapper(_kvdbDataSchemaMapper);
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(
        std::bind(&KvdbApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2)
    );
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(
        std::bind(&KvdbApiImpl::processConnectedEvent, this)
    );
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(
        std::bind(&KvdbApiImpl::processDisconnectedEvent, this)
    );
}

KvdbApiImpl::~KvdbApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
    _guardedExecutor.reset();
    LOG_TRACE("~KvdbApiImpl Done");
}

std::string KvdbApiImpl::createKvdb(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    auto ctx = prepareContainerCreate(contextId, users, managers);
    core::ModuleDataToEncryptV5 kvdbDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = ctx.secret, .resourceId = ctx.resourceId, .randomId = ctx.dio.randomId},
        .dio = ctx.dio
    };
    server::KvdbCreateModel create_kvdb_model;
    fillContainerCreateModel(
        create_kvdb_model, contextId, users, managers, ctx,
        _kvdbDataSchemaMapper->encrypt(kvdbDataToEncrypt, ctx.key.key), groups
    );
    create_kvdb_model.type = KVDB_TYPE_FILTER_FLAG;
    if (policies.has_value()) {
        create_kvdb_model.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    auto result = _serverApi.kvdbCreate(create_kvdb_model);
    return result.kvdbId;
}

void KvdbApiImpl::updateKvdb(
    const std::string& kvdbId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t version,
    const bool force,
    const bool forceGenerateNewKey,
    const std::optional<core::ContainerPolicy>& policies,
    const std::vector<core::GroupGrantWithKey>& groups
) {

    // get current kvdb
    server::KvdbGetModel getModel;
    getModel.kvdbId = kvdbId;
    auto currentKvdb = _serverApi.kvdbGet(getModel).kvdb;
    auto currentKvdbEntry = currentKvdb.data.back();
    auto currentKvdbResourceId = currentKvdb.resourceId.value_or(core::EndpointUtils::generateId());
    auto ctx = prepareContainerUpdate(
        currentKvdb, currentKvdbEntry, currentKvdbResourceId, users, managers,
        forceGenerateNewKey || doesGroupStateForceNewKey(currentKvdb, groups), true, _groupPrivKeyResolver
    );
    server::KvdbUpdateModel model;
    // The grant list is the caller's: this is the call that adds and removes group grantees, so an empty list
    // revokes every grant the KVDB had.
    fillContainerUpdateModel(model, kvdbId, currentKvdbResourceId, users, managers, ctx, version, force, groups);
    if (policies.has_value()) {
        model.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    core::ModuleDataToEncryptV5 kvdbDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta =
            core::ModuleInternalMetaV5{
                .secret = ctx.secret, .resourceId = currentKvdbResourceId, .randomId = ctx.dio.randomId
            },
        .dio = ctx.dio
    };
    model.data = _kvdbDataSchemaMapper->encrypt(kvdbDataToEncrypt, ctx.key.key);

    _serverApi.kvdbUpdate(model);
    invalidateModuleKeysInCache(kvdbId);
}

void KvdbApiImpl::rotateKvdbKeys(
    const std::string& kvdbId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const int64_t version,
    const bool force,
    const std::vector<core::GroupGrantWithKey>& groups
) {
    server::KvdbGetModel getModel;
    getModel.kvdbId = kvdbId;
    auto currentKvdb = _serverApi.kvdbGet(getModel).kvdb;
    const auto& currentEntry = currentKvdb.data.back();
    auto resourceId = currentKvdb.resourceId.value_or(core::EndpointUtils::generateId());

    auto ctx = prepareContainerUpdate(
        currentKvdb, currentEntry, resourceId, users, managers, true, true, _groupPrivKeyResolver
    );

    server::KvdbRotateKeysModel model;
    model.id = kvdbId;
    model.keyId = ctx.key.id;
    model.keys = ctx.keyEntries;
    model.version = version;
    model.force = force;

    // A re-key changes no grants, so the grantees are the KVDB's own — `currentKvdb.groups`, which the bridge
    // serves in full. Taking them from `groups` instead would silently drop every grantee the caller did not name,
    // and a caller can only name the groups it belongs to: `groupKeys`, the one place a KVDB's grantee groups
    // show up in its payload, is narrowed to those. The bridge rejects a re-key that leaves a granted group without
    // an entry at the new keyId, so the dropped grantees would fail the whole call.
    model.groupKeys = buildRekeyGroupKeyEntries(currentKvdb, resourceId, ctx, groups);

    _serverApi.kvdbRotateKeys(model);
    invalidateModuleKeysInCache(kvdbId);
}

void KvdbApiImpl::deleteKvdb(const std::string& kvdbId) {
    server::KvdbDeleteModel model{.kvdbId = kvdbId};
    _serverApi.kvdbDelete(model);
    invalidateModuleKeysInCache(kvdbId);
}

Kvdb KvdbApiImpl::getKvdb(const std::string& kvdbId) {
    server::KvdbGetModel params;
    params.kvdbId = kvdbId;
    params.type = KVDB_TYPE_FILTER_FLAG;
    auto kvdb = _serverApi.kvdbGet(params).kvdb;
    setNewModuleKeysInCache(kvdb.id, kvdbToModuleKeys(kvdb), kvdb.version);
    auto result = _kvdbDataSchemaMapper->validateDecryptAndConvertKvdb(kvdb, _keyProvider, _groupPrivKeyResolver);
    return result;
}

core::PagingList<Kvdb> KvdbApiImpl::listKvdbs(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    server::KvdbListModel model;
    model.contextId = contextId;
    model.type = KVDB_TYPE_FILTER_FLAG;
    core::ListQueryMapper::map(model, pagingQuery);
    auto kvdbsList = _serverApi.kvdbList(model);
    for (auto kvdb : kvdbsList.kvdbs) {
        setNewModuleKeysInCache(kvdb.id, kvdbToModuleKeys(kvdb), kvdb.version);
    }
    std::vector<Kvdb> kvdbs = _kvdbDataSchemaMapper->validateDecryptAndConvertKvdbs(
        kvdbsList.kvdbs, _keyProvider, _groupPrivKeyResolver
    );
    return core::PagingList<Kvdb>({.totalAvailable = kvdbsList.count, .readItems = kvdbs});
}

KvdbEntry KvdbApiImpl::getEntry(const std::string& kvdbId, const std::string& key) {
    server::KvdbEntryGetModel model{.kvdbId = kvdbId, .kvdbEntryKey = key};
    auto entry = _serverApi.kvdbEntryGet(model).kvdbEntry;
    KvdbEntry result;
    result = _entryDataSchemaMapper.validateDecryptAndConvertEntryDataToEntry(
        entry, getEntryDecryptionKeys(entry), _keyProvider, _groupPrivKeyResolver
    );
    return result;
}

bool KvdbApiImpl::hasEntry(const std::string& kvdbId, const std::string& key) {
    try {
        server::KvdbEntryGetModel model{.kvdbId = kvdbId, .kvdbEntryKey = key};
        _serverApi.kvdbEntryGet(model);
    } catch (const privmx::utils::PrivmxException& e) {
        if (core::ExceptionConverter::convert(e).getCode() ==
            privmx::endpoint::server::KvdbEntryDoesNotExistException().getCode()) {
            return false;
        }
        e.rethrow();
    }
    return true;
}

core::PagingList<std::string> KvdbApiImpl::listEntriesKeys(
    const std::string& kvdbId,
    const core::PagingQuery& pagingQuery
) {
    server::KvdbListKeysModel model;
    model.kvdbId = kvdbId;
    core::ListQueryMapper::map(model, pagingQuery);
    auto entriesList = _serverApi.kvdbListKeys(model);
    std::vector<std::string> keys;
    for (auto key : entriesList.kvdbEntryKeys) {
        keys.push_back(key);
    }
    return core::PagingList<std::string>({.totalAvailable = entriesList.count, .readItems = keys});
}

core::PagingList<KvdbEntry> KvdbApiImpl::listEntries(const std::string& kvdbId, const core::PagingQuery& pagingQuery) {
    server::KvdbListEntriesModel model;
    model.kvdbId = kvdbId;
    core::ListQueryMapper::map(model, pagingQuery);
    auto entriesList = _serverApi.kvdbListEntries(model);
    auto kvdb = entriesList.kvdb;
    _kvdbDataSchemaMapper->assertDataIntegrity(kvdb);
    setNewModuleKeysInCache(kvdb.id, kvdbToModuleKeys(kvdb), kvdb.version);
    auto entries = _entryDataSchemaMapper.validateDecryptAndConvertKvdbEntriesDataToKvdbEntries(
        entriesList.kvdbEntries, kvdbToModuleKeys(kvdb), _keyProvider, _groupPrivKeyResolver
    );
    return core::PagingList<KvdbEntry>({.totalAvailable = entriesList.count, .readItems = entries});
}

void KvdbApiImpl::setEntry(
    const std::string& kvdbId,
    const std::string& key,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    int64_t version
) {
    withKeyRefresh<void>(
        kvdbId, privmx::endpoint::server::InvalidKeyIdException().getCode(),
        [&](const core::ModuleKeys& keys) {
            setEntryRequest(kvdbId, key, publicMeta, privateMeta, data, version, keys);
        }
    );
}

void KvdbApiImpl::setEntryRequest(
    const std::string& kvdbId,
    const std::string& key,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    int64_t version,
    const core::ModuleKeys& keys
) {
    auto msgKey = getAndValidateModuleCurrentEncKey(keys, _groupPrivKeyResolver);
    if (msgKey.statusCode != 0) {
        throw core::EncryptionKeyValidationException(
            "Current encryption key statusCode: " + std::to_string(msgKey.statusCode)
        );
    }
    server::KvdbEntrySetModel send_entry_model;
    send_entry_model.kvdbId = kvdbId;
    send_entry_model.kvdbEntryKey = key;
    send_entry_model.version = version;
    send_entry_model.keyId = msgKey.id;
    send_entry_model.kvdbEntryValue = encryptEntryData(kvdbId, key, publicMeta, privateMeta, data, keys);
    _serverApi.kvdbEntrySet(send_entry_model);
}

void KvdbApiImpl::deleteEntry(const std::string& kvdbId, const std::string& key) {
    server::KvdbEntryDeleteModel model;
    model.kvdbId = kvdbId;
    model.kvdbEntryKey = key;
    _serverApi.kvdbEntryDelete(model);
}

std::map<std::string, bool> KvdbApiImpl::deleteEntries(
    const std::string& kvdbId,
    const std::vector<std::string>& keys
) {
    server::KvdbEntryDeleteManyModel model;
    model.kvdbId = kvdbId;
    for (auto key : keys) {
        model.kvdbEntryKeys.push_back(key);
    }
    auto deleteStatuses = _serverApi.kvdbEntryDeleteMany(model).results;
    std::map<std::string, bool> result;
    for (auto deleteStatus : deleteStatuses) {
        result.insert(std::make_pair(deleteStatus.kvdbEntryKey, deleteStatus.status == "OK"));
    }
    return result;
}

void KvdbApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    auto subscriptionQuery = _subscriber.getSubscriptionQuery(notification.subscriptions);
    if (!subscriptionQuery.has_value()) {
        return;
    }
    _guardedExecutor->exec([&, type, notification]() {
        if (type == "kvdbCreated") {
            auto raw = server::KvdbInfo::fromJSON(notification.data);
            if (raw.type.value_or(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, kvdbToModuleKeys(raw), raw.version);
                privmx::endpoint::kvdb::Kvdb data = _kvdbDataSchemaMapper->validateDecryptAndConvertKvdb(
                    raw, _keyProvider, _groupPrivKeyResolver
                );
                auto event = core::EventBuilder::buildEvent<KvdbCreatedEvent>("kvdb", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "kvdbUpdated") {
            auto raw = server::KvdbInfo::fromJSON(notification.data);
            if (raw.type.value_or(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, kvdbToModuleKeys(raw), raw.version);
                privmx::endpoint::kvdb::Kvdb data = _kvdbDataSchemaMapper->validateDecryptAndConvertKvdb(
                    raw, _keyProvider, _groupPrivKeyResolver
                );
                auto event = core::EventBuilder::buildEvent<KvdbUpdatedEvent>("kvdb", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "kvdbDeleted") {
            auto raw = server::KvdbDeletedEventData::fromJSON(notification.data);
            if (raw.type.value_or(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
                invalidateModuleKeysInCache(raw.kvdbId);
                auto data = Mapper::mapToKvdbDeletedEventData(raw);
                auto event = core::EventBuilder::buildEvent<KvdbDeletedEvent>("kvdb", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "kvdbStats") {
            auto raw = server::KvdbStatsEventData::fromJSON(notification.data);
            if (raw.type.value_or(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
                auto data = Mapper::mapToKvdbStatsEventData(raw);
                auto event = core::EventBuilder::buildEvent<KvdbStatsChangedEvent>("kvdb", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "kvdbNewEntry") {
            auto raw = server::KvdbEntryEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
                auto data = _entryDataSchemaMapper.validateDecryptAndConvertEntryDataToEntry(
                    raw, getEntryDecryptionKeys(raw), _keyProvider, _groupPrivKeyResolver
                );
                auto event = core::EventBuilder::buildEvent<KvdbNewEntryEvent>(
                    "kvdb/" + raw.kvdbId + "/entries", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "kvdbUpdatedEntry") {
            auto raw = server::KvdbEntryEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
                auto data = _entryDataSchemaMapper.validateDecryptAndConvertEntryDataToEntry(
                    raw, getEntryDecryptionKeys(raw), _keyProvider, _groupPrivKeyResolver
                );
                auto event = core::EventBuilder::buildEvent<KvdbEntryUpdatedEvent>(
                    "kvdb/" + raw.kvdbId + "/entries", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "kvdbDeletedEntry") {
            auto raw = server::KvdbDeletedEntryEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
                auto data = Mapper::mapToKvdbDeletedEntryEventData(raw);
                auto event = core::EventBuilder::buildEvent<KvdbEntryDeletedEvent>(
                    "kvdb/" + raw.kvdbId + "/entries", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "kvdbCollectionChanged") {
            auto raw = core::server::CollectionChangedEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
                auto data = core::Mapper::mapToCollectionChangedEventData(KVDB_TYPE_FILTER_FLAG, raw);
                auto event = core::EventBuilder::buildEvent<core::CollectionChangedEvent>(
                    "kvdb/collectionChanged", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        }
    });
}

void KvdbApiImpl::processConnectedEvent() {
    invalidateModuleKeysInCache();
}

void KvdbApiImpl::processDisconnectedEvent() {
    LOG_TRACE("KvdbApiImpl recived DisconnectedEvent");
    invalidateModuleKeysInCache();
    privmx::utils::ManualManagedClass<KvdbApiImpl>::cleanup();
}

std::tuple<Kvdb, core::DataIntegrityObject> KvdbApiImpl::decryptAndConvertKvdbDataToKvdb(
    server::KvdbInfo kvdb,
    const core::DecryptedEncKey& encKey
) {
    return _kvdbDataSchemaMapper->decrypt(kvdb, encKey);
}

core::ModuleKeys KvdbApiImpl::getEntryDecryptionKeys(server::KvdbEntryInfo entry) {
    auto keyId = entry.keyId;
    kvdb::KvdbDataSchema::Version minimumKvdbSchemaVersion;
    switch (_entryDataSchemaMapper.getDataStructureVersion(entry)) {
    case kvdb::KvdbEntryDataSchema::Version::UNKNOWN:
        minimumKvdbSchemaVersion = kvdb::KvdbDataSchema::UNKNOWN;
        break;
    case kvdb::KvdbEntryDataSchema::Version::VERSION_5:
        minimumKvdbSchemaVersion = kvdb::KvdbDataSchema::VERSION_5;
        break;
    }
    return getModuleKeysForItem(entry.kvdbId, keyId, minimumKvdbSchemaVersion);
}

Poco::Dynamic::Var KvdbApiImpl::encryptEntryData(
    const std::string& kvdbId,
    const std::string& resourceId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const core::ModuleKeys& kvdbKeys
) {
    core::DecryptedEncKeyV2 msgKey = getAndValidateModuleCurrentEncKey(kvdbKeys, _groupPrivKeyResolver);
    return _entryDataSchemaMapper.encrypt(
        kvdbId, resourceId, kvdbKeys.contextId, kvdbKeys.moduleResourceId, publicMeta, privateMeta, data, msgKey
    );
}

void KvdbApiImpl::assertKvdbExist(const std::string& kvdbId) {
    kvdb::server::KvdbGetModel params{.kvdbId = kvdbId, .type = std::nullopt};
    _serverApi.kvdbGet(params);
}

std::pair<core::ModuleKeys, int64_t> KvdbApiImpl::getModuleKeysAndVersionFromServer(std::string moduleId) {
    kvdb::server::KvdbGetModel params{.kvdbId = moduleId, .type = std::nullopt};
    auto kvdb = _serverApi.kvdbGet(params).kvdb;
    // validate kvdb Data before returning data
    _kvdbDataSchemaMapper->assertDataIntegrity(kvdb);
    return std::make_pair(kvdbToModuleKeys(kvdb), kvdb.version);
}

core::ModuleKeys KvdbApiImpl::kvdbToModuleKeys(server::KvdbInfo kvdb) {
    return core::ModuleKeys{
        .keys = kvdb.keys,
        .groupKeys = kvdb.groupKeys,
        .staleGroups = kvdb.staleGroups,
        .currentKeyId = kvdb.keyId,
        .moduleSchemaVersion = _kvdbDataSchemaMapper->getDataStructureVersion(kvdb.data.back()),
        .moduleResourceId = kvdb.resourceId.value_or(""),
        .contextId = kvdb.contextId
    };
}

std::vector<std::string> KvdbApiImpl::subscribeFor(const std::vector<std::string>& subscriptionQueries) {
    auto result = _subscriber.subscribeFor(subscriptionQueries);
    _eventMiddleware->notificationEventListenerAddSubscriptionIds(_notificationListenerId, result);
    return result;
}

void KvdbApiImpl::unsubscribeFrom(const std::vector<std::string>& subscriptionIds) {
    _subscriber.unsubscribeFrom(subscriptionIds);
    _eventMiddleware->notificationEventListenerRemoveSubscriptionIds(_notificationListenerId, subscriptionIds);
}

std::string KvdbApiImpl::buildSubscriptionQuery(
    EventType eventType,
    EventSelectorType selectorType,
    const std::string& selectorId
) {
    return SubscriberImpl::buildQuery(eventType, selectorType, selectorId);
}

std::string KvdbApiImpl::buildSubscriptionQueryForSelectedEntry(
    EventType eventType,
    const std::string& kvdbId,
    const std::string& kvdbEntryKey
) {
    return SubscriberImpl::buildQueryForSelectedEntry(eventType, kvdbId, kvdbEntryKey);
}
