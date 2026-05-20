/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/utils/Debug.hpp>
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
    const core::Connection& connection
)
    : ModuleBaseApi(userPrivKey, keyProvider, host, eventMiddleware, connection), _gateway(gateway),
      _userPrivKey(userPrivKey), _keyProvider(keyProvider), _host(host), _eventMiddleware(eventMiddleware),
      _connection(connection), _serverApi(ServerApi(gateway)), _subscriber(gateway, KVDB_TYPE_FILTER_FLAG),
      _kvdbDataSchemaMapper(userPrivKey, connection), _entryDataSchemaMapper(userPrivKey, connection) {
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
    const std::optional<core::ContainerPolicy>& policies
) {
    return createKvdbEx(contextId, users, managers, publicMeta, privateMeta, KVDB_TYPE_FILTER_FLAG, policies);
}

std::string KvdbApiImpl::createKvdbEx(
    const std::string& contextId,
    const std::vector<core::UserWithPubKey>& users,
    const std::vector<core::UserWithPubKey>& managers,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const std::string& type,
    const std::optional<core::ContainerPolicy>& policies
) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, _createKvdbEx)
    auto kvdbKey = _keyProvider->generateKey();
    std::string resourceId = core::EndpointUtils::generateId();
    auto kvdbDIO = _connection.getImpl()->createDIO(contextId, resourceId);
    auto kvdbSecret = _keyProvider->generateSecret();

    core::ModuleDataToEncryptV5 kvdbDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::
            ModuleInternalMetaV5{.secret = kvdbSecret, .resourceId = resourceId, .randomId = kvdbDIO.randomId},
        .dio = kvdbDIO
    };
    server::KvdbCreateModel create_kvdb_model;
    create_kvdb_model.resourceId = resourceId;
    create_kvdb_model.contextId = contextId;
    create_kvdb_model.keyId = kvdbKey.id;
    create_kvdb_model.data = _kvdbDataSchemaMapper.encrypt(kvdbDataToEncrypt, kvdbKey.key);
    auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    create_kvdb_model.keys = _keyProvider->prepareKeysList(
        allUsers, kvdbKey, kvdbDIO, {.contextId = contextId, .resourceId = resourceId}, kvdbSecret
    );
    create_kvdb_model.users = mapUsers(users);
    create_kvdb_model.managers = mapUsers(managers);
    if (type.length() > 0) {
        create_kvdb_model.type = type;
    }
    if (policies.has_value()) {
        create_kvdb_model.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _createKvdbEx, data encrypted)
    auto result = _serverApi.kvdbCreate(create_kvdb_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, _createKvdbEx, data send)
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
    const std::optional<core::ContainerPolicy>& policies
) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, updateKvdb)

    // get current kvdb
    server::KvdbGetModel getModel;
    getModel.kvdbId = kvdbId;
    auto currentKvdb = _serverApi.kvdbGet(getModel).kvdb;
    auto currentKvdbEntry = currentKvdb.data.back();
    auto currentKvdbResourceId = currentKvdb.resourceId;
    auto location{getModuleEncKeyLocation(currentKvdb, currentKvdbResourceId)};
    auto kvdbKeys{getAndValidateModuleKeys(currentKvdb, currentKvdbResourceId)};
    auto currentKvdbKey{findEncKeyByKeyId(kvdbKeys, currentKvdbEntry.keyId)};
    auto kvdbInternalMeta = extractAndDecryptModuleInternalMeta(currentKvdbEntry, currentKvdbKey);

    auto usersKeysResolver{
        core::UsersKeysResolver::create(currentKvdb, users, managers, forceGenerateNewKey, currentKvdbKey)
    };

    if (!_keyProvider->verifyKeysSecret(kvdbKeys, location, kvdbInternalMeta.secret)) {
        throw KvdbEncryptionKeyValidationException();
    }
    // setting kvdb Key adding new users
    core::EncKey kvdbKey = currentKvdbKey;
    core::DataIntegrityObject updateKvdbDio = _connection.getImpl()->createDIO(
        currentKvdb.contextId, currentKvdbResourceId
    );
    std::vector<core::server::KeyEntrySet> keys;
    if (usersKeysResolver->doNeedNewKey()) {
        kvdbKey = _keyProvider->generateKey();
        keys = _keyProvider->prepareKeysList(
            usersKeysResolver->getNewUsers(), kvdbKey, updateKvdbDio, location, kvdbInternalMeta.secret
        );
    }

    auto usersToAddMissingKey{usersKeysResolver->getUsersToAddKey()};
    if (usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            kvdbKeys, usersToAddMissingKey, updateKvdbDio, location, kvdbInternalMeta.secret
        );
        for (auto t : tmp)
            keys.push_back(t);
    }
    server::KvdbUpdateModel model;
    std::vector<std::string> usersList;
    for (auto user : users) {
        usersList.push_back(user.userId);
    }
    std::vector<std::string> managersList;
    for (auto x : managers) {
        managersList.push_back(x.userId);
    }
    model.id = kvdbId;
    model.resourceId = currentKvdbResourceId;
    model.keyId = kvdbKey.id;
    model.keys = keys;
    model.users = usersList;
    model.managers = managersList;
    model.version = version;
    model.force = force;
    if (policies.has_value()) {
        model.policy = privmx::endpoint::core::Factory::createPolicyServerObject(policies.value());
    }
    core::ModuleDataToEncryptV5 kvdbDataToEncrypt{
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta =
            core::ModuleInternalMetaV5{
                .secret = kvdbInternalMeta.secret,
                .resourceId = currentKvdbResourceId,
                .randomId = updateKvdbDio.randomId
            },
        .dio = updateKvdbDio
    };
    model.data = _kvdbDataSchemaMapper.encrypt(kvdbDataToEncrypt, kvdbKey.key);

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, updateKvdb, data encrypted)
    _serverApi.kvdbUpdate(model);
    invalidateModuleKeysInCache(kvdbId);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, updateKvdb, data send)
}

void KvdbApiImpl::deleteKvdb(const std::string& kvdbId) {
    server::KvdbDeleteModel model{.kvdbId = kvdbId};
    _serverApi.kvdbDelete(model);
    invalidateModuleKeysInCache(kvdbId);
}

Kvdb KvdbApiImpl::getKvdb(const std::string& kvdbId) {
    return getKvdbEx(kvdbId, KVDB_TYPE_FILTER_FLAG);
}

Kvdb KvdbApiImpl::getKvdbEx(const std::string& kvdbId, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, getKvdbEx)
    server::KvdbGetModel params;
    params.kvdbId = kvdbId;
    if (type.length() > 0) {
        params.type = type;
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _getKvdbEx, getting kvdb)
    auto kvdb = _serverApi.kvdbGet(params).kvdb;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _getKvdbEx, data send)
    setNewModuleKeysInCache(kvdb.id, kvdbToModuleKeys(kvdb), kvdb.version);
    auto result = _kvdbDataSchemaMapper.validateDecryptAndConvertKvdb(kvdb, _keyProvider);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _getKvdbEx, data decrypted)
    return result;
}

core::PagingList<Kvdb> KvdbApiImpl::listKvdbs(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    return listKvdbsEx(contextId, pagingQuery, KVDB_TYPE_FILTER_FLAG);
}

core::PagingList<Kvdb> KvdbApiImpl::listKvdbsEx(
    const std::string& contextId,
    const core::PagingQuery& pagingQuery,
    const std::string& type
) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, _listKvdbsEx)
    server::KvdbListModel model;
    model.contextId = contextId;
    if (type.length() > 0) {
        model.type = type;
    }
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _listKvdbsEx, getting kvdbList)
    auto kvdbsList = _serverApi.kvdbList(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _listKvdbsEx, data send)
    for (auto kvdb : kvdbsList.kvdbs) {
        setNewModuleKeysInCache(kvdb.id, kvdbToModuleKeys(kvdb), kvdb.version);
    }
    std::vector<Kvdb> kvdbs = _kvdbDataSchemaMapper.validateDecryptAndConvertKvdbs(kvdbsList.kvdbs, _keyProvider);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, _listKvdbsEx, data decrypted)
    return core::PagingList<Kvdb>({.totalAvailable = kvdbsList.count, .readItems = kvdbs});
}

KvdbEntry KvdbApiImpl::getEntry(const std::string& kvdbId, const std::string& key) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, getEntry)
    server::KvdbEntryGetModel model{.kvdbId = kvdbId, .kvdbEntryKey = key};
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, getting entry)
    auto entry = _serverApi.kvdbEntryGet(model).kvdbEntry;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, data recived);
    KvdbEntry result;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, getting kvdb)
    result = _entryDataSchemaMapper.validateDecryptAndConvertEntryDataToEntry(entry, getEntryDecryptionKeys(entry), _keyProvider);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, getEntry, data decrypted)
    return result;
}

bool KvdbApiImpl::hasEntry(const std::string& kvdbId, const std::string& key) {
    try {
        server::KvdbEntryGetModel model{.kvdbId = kvdbId, .kvdbEntryKey = key};
        PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, getting entry)
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
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, listEntriesKeys)
    server::KvdbListKeysModel model;
    model.kvdbId = kvdbId;
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, getting entriesList)
    auto entriesList = _serverApi.kvdbListKeys(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, data send)
    std::vector<std::string> keys;
    for (auto key : entriesList.kvdbEntryKeys) {
        keys.push_back(key);
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, listEntriesKeys, data decrypted)
    return core::PagingList<std::string>({.totalAvailable = entriesList.count, .readItems = keys});
}

core::PagingList<KvdbEntry> KvdbApiImpl::listEntries(const std::string& kvdbId, const core::PagingQuery& pagingQuery) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, listEntry)
    server::KvdbListEntriesModel model;
    model.kvdbId = kvdbId;
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntry, getting listEntry)
    auto entriesList = _serverApi.kvdbListEntries(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, data send)
    auto kvdb = entriesList.kvdb;
    _kvdbDataSchemaMapper.assertDataIntegrity(kvdb);
    setNewModuleKeysInCache(kvdb.id, kvdbToModuleKeys(kvdb), kvdb.version);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, data send)
    auto entries = _entryDataSchemaMapper.validateDecryptAndConvertKvdbEntriesDataToKvdbEntries(
        entriesList.kvdbEntries, kvdbToModuleKeys(kvdb), _keyProvider
    );
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, listEntriesKeys, data decrypted)
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
    try {
        auto currentKeys{getModuleKeys(kvdbId)};
        return setEntryRequest(kvdbId, key, publicMeta, privateMeta, data, version, currentKeys);
    } catch (const privmx::utils::PrivmxException& e) {
        if (core::ExceptionConverter::convert(e).getCode() ==
            privmx::endpoint::server::InvalidKeyIdException().getCode()) {
            auto newestKeys{getNewModuleKeysAndUpdateCache(kvdbId)};
            return setEntryRequest(kvdbId, key, publicMeta, privateMeta, data, version, newestKeys);
        }
        e.rethrow();
    }
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
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, sendEntry);
    auto msgKey = getAndValidateModuleCurrentEncKey(keys);
    if (msgKey.statusCode != 0) {
        throw KvdbEncryptionKeyValidationException(
            "Current encryption key statusCode: " + std::to_string(msgKey.statusCode)
        );
    }
    server::KvdbEntrySetModel send_entry_model;
    send_entry_model.kvdbId = kvdbId;
    send_entry_model.kvdbEntryKey = key;
    send_entry_model.version = version;
    send_entry_model.keyId = msgKey.id;
    send_entry_model.kvdbEntryValue = encryptEntryData(kvdbId, key, publicMeta, privateMeta, data, keys);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, sendEntry, data encrypted)
    _serverApi.kvdbEntrySet(send_entry_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, sendEntry, data send)
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
                privmx::endpoint::kvdb::Kvdb data = _kvdbDataSchemaMapper.validateDecryptAndConvertKvdb(raw, _keyProvider);
                auto event = core::EventBuilder::buildEvent<KvdbCreatedEvent>("kvdb", data, notification);
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "kvdbUpdated") {
            auto raw = server::KvdbInfo::fromJSON(notification.data);
            if (raw.type.value_or(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
                setNewModuleKeysInCache(raw.id, kvdbToModuleKeys(raw), raw.version);
                privmx::endpoint::kvdb::Kvdb data = _kvdbDataSchemaMapper.validateDecryptAndConvertKvdb(raw, _keyProvider);
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
                auto data = _entryDataSchemaMapper.validateDecryptAndConvertEntryDataToEntry(raw, getEntryDecryptionKeys(raw), _keyProvider);
                auto event = core::EventBuilder::buildEvent<KvdbNewEntryEvent>(
                    "kvdb/" + raw.kvdbId + "/entries", data, notification
                );
                _eventMiddleware->emitApiEvent(event);
            }
        } else if (type == "kvdbUpdatedEntry") {
            auto raw = server::KvdbEntryEventData::fromJSON(notification.data);
            if (raw.containerType.value_or(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
                auto data = _entryDataSchemaMapper.validateDecryptAndConvertEntryDataToEntry(raw, getEntryDecryptionKeys(raw), _keyProvider);
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

std::vector<std::string> KvdbApiImpl::mapUsers(const std::vector<core::UserWithPubKey>& users) {
    std::vector<std::string> result;
    for (auto user : users) {
        result.push_back(user.userId);
    }
    return result;
}

Kvdb KvdbApiImpl::convertServerKvdbToLibKvdb(
    server::KvdbInfo kvdb,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const int64_t& statusCode,
    const int64_t& schemaVersion
) {
    return KvdbDataSchemaStrategyV5::toLibKvdb(kvdb, publicMeta, privateMeta, statusCode, schemaVersion);
}

KvdbDataSchema::Version KvdbApiImpl::getKvdbDataEntryStructureVersion(server::KvdbDataEntry kvdbEntry) {
    return _kvdbDataSchemaMapper.getDataStructureVersion(kvdbEntry);
}

std::tuple<Kvdb, core::DataIntegrityObject> KvdbApiImpl::decryptAndConvertKvdbDataToKvdb(
    server::KvdbInfo kvdb,
    const core::DecryptedEncKey& encKey
) {
    return _kvdbDataSchemaMapper.decrypt(kvdb, encKey);
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
    return getModuleKeys(entry.kvdbId, std::set<std::string>{keyId}, minimumKvdbSchemaVersion);
}

Poco::Dynamic::Var KvdbApiImpl::encryptEntryData(
    const std::string& kvdbId,
    const std::string& resourceId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& data,
    const core::ModuleKeys& kvdbKeys
) {
    core::DecryptedEncKeyV2 msgKey = getAndValidateModuleCurrentEncKey(kvdbKeys);
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
    _kvdbDataSchemaMapper.assertDataIntegrity(kvdb);
    return std::make_pair(kvdbToModuleKeys(kvdb), kvdb.version);
}

core::ModuleKeys KvdbApiImpl::kvdbToModuleKeys(server::KvdbInfo kvdb) {
    return core::ModuleKeys{
        .keys = kvdb.keys,
        .currentKeyId = kvdb.keyId,
        .moduleSchemaVersion = getKvdbDataEntryStructureVersion(kvdb.data.back()),
        .moduleResourceId = kvdb.resourceId,
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
