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

#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventMiddleware.hpp>
#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>

#include "privmx/endpoint/kvdb/KvdbApiImpl.hpp"
#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include "privmx/endpoint/kvdb/KvdbVarSerializer.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include "privmx/endpoint/kvdb/Mapper.hpp"
#include "privmx/endpoint/core/ListQueryMapper.hpp"

using namespace privmx::endpoint;
using namespace kvdb;

KvdbApiImpl::KvdbApiImpl(
    const privfs::RpcGateway::Ptr& gateway,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::shared_ptr<core::KeyProvider>& keyProvider,
    const std::string& host,
    const std::shared_ptr<core::EventMiddleware>& eventMiddleware,
    const std::shared_ptr<core::EventChannelManager>& eventChannelManager,
    const core::Connection& connection
) : _gateway(gateway),
    _userPrivKey(userPrivKey),
    _keyProvider(keyProvider),
    _host(host),
    _eventMiddleware(eventMiddleware),
    _connection(connection),
    _serverApi(ServerApi(gateway)),
    _kvdbProvider(KvdbProvider(
        [&](const std::string& id) {
            auto model = privmx::utils::TypedObjectFactory::createNewObject<server::KvdbGetModel>();
            model.kvdbId(id);
            auto serverKvdb = _serverApi.kvdbGet(model).kvdb();
            return serverKvdb;
        },
        std::bind(&KvdbApiImpl::validateKvdbDataIntegrity, this, std::placeholders::_1)
    )),
    _subscribeForKvdb(false),
    _kvdbSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "kvdb"))
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&KvdbApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2));
    _connectedListenerId = _eventMiddleware->addConnectedEventListener(std::bind(&KvdbApiImpl::processConnectedEvent, this));
    _disconnectedListenerId = _eventMiddleware->addDisconnectedEventListener(std::bind(&KvdbApiImpl::processDisconnectedEvent, this));
}

KvdbApiImpl::~KvdbApiImpl() {
    _eventMiddleware->removeNotificationEventListener(_notificationListenerId);
    _eventMiddleware->removeConnectedEventListener(_connectedListenerId);
    _eventMiddleware->removeDisconnectedEventListener(_disconnectedListenerId);
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
    auto kvdbDIO = _connection.getImpl()->createDIO(
        contextId,
        resourceId
    );
    auto kvdbSecret = _keyProvider->generateSecret();

    KvdbDataToEncryptV5 kvdbDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = KvdbInternalMetaV5{.secret=kvdbSecret, .resourceId=resourceId, .randomId=kvdbDIO.randomId},
        .dio = kvdbDIO
    };
    auto create_kvdb_model = utils::TypedObjectFactory::createNewObject<server::KvdbCreateModel>();
    create_kvdb_model.resourceId(resourceId);
    create_kvdb_model.contextId(contextId);
    create_kvdb_model.keyId(kvdbKey.id);
    create_kvdb_model.data(_kvdbDataEncryptorV5.encrypt(kvdbDataToEncrypt, _userPrivKey, kvdbKey.key).asVar());
    auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    create_kvdb_model.keys(
        _keyProvider->prepareKeysList(
            allUsers, 
            kvdbKey, 
            kvdbDIO,
            {.contextId=contextId, .resourceId=resourceId},
            kvdbSecret
        )
    );

    create_kvdb_model.users(mapUsers(users));
    create_kvdb_model.managers(mapUsers(managers));
    if (type.length() > 0) {
        create_kvdb_model.type(type);
    }
    if (policies.has_value()) {
        create_kvdb_model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _createKvdbEx, data encrypted)
    auto result = _serverApi.kvdbCreate(create_kvdb_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, _createKvdbEx, data send)
    return result.kvdbId();
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

    auto getModel = utils::TypedObjectFactory::createNewObject<server::KvdbGetModel>();
    getModel.kvdbId(kvdbId);
    auto currentKvdb = _serverApi.kvdbGet(getModel).kvdb();
    auto currentKvdbResourceId = currentKvdb.resourceIdOpt(core::EndpointUtils::generateId());

    // extract current users info
    auto usersVec {core::EndpointUtils::listToVector<std::string>(currentKvdb.users())};
    auto managersVec {core::EndpointUtils::listToVector<std::string>(currentKvdb.managers())};
    auto oldUsersAll {core::EndpointUtils::uniqueList(usersVec, managersVec)};

    auto new_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);

    // adjust key
    std::vector<std::string> deletedUsers {core::EndpointUtils::getDifference(oldUsersAll, core::EndpointUtils::usersWithPubKeyToIds(new_users))};
    std::vector<std::string> addedUsers {core::EndpointUtils::getDifference(core::EndpointUtils::usersWithPubKeyToIds(new_users), oldUsersAll)};
    std::vector<core::UserWithPubKey> usersToAddMissingKey;
    for(auto new_user: new_users) {
        if( std::find(addedUsers.begin(), addedUsers.end(), new_user.userId) != addedUsers.end()) {
            usersToAddMissingKey.push_back(new_user);
        }
    }
    bool needNewKey = deletedUsers.size() > 0 || forceGenerateNewKey;

    // read all key to check if all key belongs to this kvdb
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=currentKvdb.contextId(), .resourceId=currentKvdbResourceId};
    keyProviderRequest.addAll(currentKvdb.keys(), location);
    auto kvdbKeys {_keyProvider->getKeysAndVerify(keyProviderRequest).at(location)};
    auto currentKvdbEntry = currentKvdb.data().get(currentKvdb.data().size()-1);
    core::DecryptedEncKey currentKvdbKey;
    for (auto key : kvdbKeys) {
        if (currentKvdbEntry.keyId() == key.first) {
            currentKvdbKey = key.second;
            break;
        }
    }
    auto kvdbInternalMeta = decryptKvdbInternalMeta(currentKvdbEntry, currentKvdbKey);
    if(currentKvdbKey.dataStructureVersion != 2) {
        //force update all keys if kvdb keys is in older version
        usersToAddMissingKey = new_users;
    }
    if(!_keyProvider->verifyKeysSecret(kvdbKeys, location, kvdbInternalMeta.secret)) {
        throw KvdbEncryptionKeyValidationException();
    }
    // setting kvdb Key adding new users
    core::EncKey kvdbKey = currentKvdbKey;
    core::DataIntegrityObject updateKvdbDio = _connection.getImpl()->createDIO(currentKvdb.contextId(), currentKvdbResourceId);
    privmx::utils::List<core::server::KeyEntrySet> keys = utils::TypedObjectFactory::createNewList<core::server::KeyEntrySet>();
    if(needNewKey) {
        kvdbKey = _keyProvider->generateKey();
        keys = _keyProvider->prepareKeysList(
            new_users, 
            kvdbKey, 
            updateKvdbDio,
            location,
            kvdbInternalMeta.secret
        );
    }
    if(usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            kvdbKeys,
            usersToAddMissingKey, 
            updateKvdbDio, 
            location,
            kvdbInternalMeta.secret
        );
        for(auto t: tmp) keys.add(t);
    }
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbUpdateModel>();
    auto usersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user: users) {
        usersList.add(user.userId);
    }
    auto managersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto x: managers) {
        managersList.add(x.userId);
    }
    model.id(kvdbId);
    model.resourceId(currentKvdbResourceId);
    model.keyId(kvdbKey.id);
    model.keys(keys);
    model.users(usersList);
    model.managers(managersList);
    model.version(version);
    model.force(force);
    if (policies.has_value()) {
        model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    KvdbDataToEncryptV5 kvdbDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = KvdbInternalMetaV5{.secret=kvdbInternalMeta.secret, .resourceId=currentKvdbResourceId, .randomId=updateKvdbDio.randomId},
        .dio = updateKvdbDio
    };
    model.data(_kvdbDataEncryptorV5.encrypt(kvdbDataToEncrypt, _userPrivKey, kvdbKey.key).asVar());

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, updateKvdb, data encrypted)
    _serverApi.kvdbUpdate(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, updateKvdb, data send)
}

void KvdbApiImpl::deleteKvdb(const std::string& kvdbId) {
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbDeleteModel>();
    model.kvdbId(kvdbId);
    _serverApi.kvdbDelete(model);
}

Kvdb KvdbApiImpl::getKvdb(const std::string& kvdbId) {
    return getKvdbEx(kvdbId, KVDB_TYPE_FILTER_FLAG);
}

Kvdb KvdbApiImpl::getKvdbEx(const std::string& kvdbId, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, getKvdbEx)
    Poco::JSON::Object::Ptr params = new Poco::JSON::Object();
    params->set("kvdbId", kvdbId);
    if (type.length() > 0) {
        params->set("type", type);
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb,_getKvdbEx, getting kvdb)
    auto kvdb = _serverApi.kvdbGet(params).kvdb();
    if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValue(kvdb);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _getKvdbEx, data send)
    auto statusCode = validateKvdbDataIntegrity(kvdb);
    if(statusCode != 0) {
        if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValueAndStatus(KvdbProvider::ContainerInfo{.container=kvdb, .status=core::DataIntegrityStatus::ValidationFailed});
        return Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode, {}};
    } else {
        if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValueAndStatus(KvdbProvider::ContainerInfo{.container=kvdb, .status=core::DataIntegrityStatus::ValidationSucceed});
    }
    auto result = decryptAndConvertKvdbDataToKvdb(kvdb);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _getKvdbEx, data decrypted)
    return result;
    
}

core::PagingList<Kvdb> KvdbApiImpl::listKvdbs(const std::string& contextId, const core::PagingQuery& pagingQuery) {
    return listKvdbsEx(contextId, pagingQuery, KVDB_TYPE_FILTER_FLAG);
}

core::PagingList<Kvdb> KvdbApiImpl::listKvdbsEx(const std::string& contextId, const core::PagingQuery& pagingQuery, const std::string& type) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, _listKvdbsEx)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbListModel>();
    model.contextId(contextId);
    if (type.length() > 0) {
        model.type(type);
    }
    core::ListQueryMapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _listKvdbsEx, getting kvdbList)
    auto kvdbsList = _serverApi.kvdbList(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, _listKvdbsEx, data send)
    std::vector<Kvdb> kvdbs;
    for (size_t i = 0; i < kvdbsList.kvdbs().size(); i++) {
        auto kvdb = kvdbsList.kvdbs().get(i);
        if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValue(kvdb);
        auto statusCode = validateKvdbDataIntegrity(kvdb);
        kvdbs.push_back(Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode, {}});
        if(statusCode == 0) {
            if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValueAndStatus(KvdbProvider::ContainerInfo{.container=kvdb, .status=core::DataIntegrityStatus::ValidationSucceed});
        } else {
            if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateByValueAndStatus(KvdbProvider::ContainerInfo{.container=kvdb, .status=core::DataIntegrityStatus::ValidationFailed});
            kvdbsList.kvdbs().remove(i);
            i--;
        }
    }
    auto tmp = decryptAndConvertKvdbsDataToKvdbs(kvdbsList.kvdbs());
    for(size_t j = 0, i = 0; i < kvdbs.size(); i++) {
        if(kvdbs[i].statusCode == 0) {
            kvdbs[i] = tmp[j];
            j++;
        }
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, _listKvdbsEx, data decrypted)
    return core::PagingList<Kvdb>({
        .totalAvailable = kvdbsList.count(),
        .readItems = kvdbs
    });
}

KvdbEntry KvdbApiImpl::getEntry(const std::string& kvdbId, const std::string& key) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, getEntry)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbEntryGetModel>();
    model.kvdbId(kvdbId);
    model.kvdbEntryKey(key);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, getting entry)
    auto entry = _serverApi.kvdbEntryGet(model).kvdbEntry();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, data recived);
    privmx::endpoint::kvdb::server::KvdbInfo kvdb;
    KvdbEntry result;
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, getting kvdb)
    kvdb = getRawKvdbFromCacheOrBridge(kvdbId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getEntry, decrypting entry)
    auto statusCode = validateEntryDataIntegrity(entry, kvdb.resourceId());
    if(statusCode != 0) {
        PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, getEntry, data integrity validation failed)
        result.statusCode = statusCode;
        return result;
    }
    result = decryptAndConvertEntryDataToEntry(kvdb, entry);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, getEntry, data decrypted)
    return result;
}

core::PagingList<std::string> KvdbApiImpl::listEntriesKeys(const std::string& kvdbId, const kvdb::KvdbKeysPagingQuery& pagingQuery) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, listEntriesKeys)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbListKeysModel>();
    model.kvdbId(kvdbId);
    kvdb::Mapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, getting entriesList)
    auto entriesList = _serverApi.kvdbListKeys(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, data send)
    std::vector<std::string> keys;
    for(auto key : entriesList.kvdbEntryKeys()) {
        keys.push_back(key);
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, listEntriesKeys, data decrypted)
    return core::PagingList<std::string>({
        .totalAvailable = entriesList.count(),
        .readItems = keys
    });
}

core::PagingList<KvdbEntry> KvdbApiImpl::listEntries(const std::string& kvdbId, const kvdb::KvdbEntryPagingQuery& pagingQuery) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, listEntry)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbListEntriesModel>();
    model.kvdbId(kvdbId);
    kvdb::Mapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntry, getting listEntry)
    auto entriesList = _serverApi.kvdbListEntries(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, data send)
    auto kvdb = entriesList.kvdb();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listEntriesKeys, data send)
    auto entries = decryptAndConvertKvdbEntriesDataToKvdbEntries(kvdb, entriesList.kvdbEntries());
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, listEntriesKeys, data decrypted)
    return core::PagingList<KvdbEntry>({
        .totalAvailable = entriesList.count(),
        .readItems = entries
    });
}

void KvdbApiImpl::setEntry(const std::string& kvdbId, const std::string& key, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data, int64_t version) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, sendEntry);
    auto kvdb = getRawKvdbFromCacheOrBridge(kvdbId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, sendEntry, getKvdb)
    auto msgKey = getKvdbCurrentEncKey(kvdb);
    auto  send_entry_model = utils::TypedObjectFactory::createNewObject<server::KvdbEntrySetModel>();
    send_entry_model.kvdbId(kvdb.id());
    send_entry_model.kvdbEntryKey(key);
    send_entry_model.version(version);
    send_entry_model.keyId(msgKey.id);
    privmx::endpoint::core::DataIntegrityObject entryDIO = _connection.getImpl()->createDIO(
        kvdb.contextId(),
        key,
        kvdbId,
        kvdb.resourceId()
    );
    KvdbEntryDataToEncryptV5 entryData {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .data = data,
        .internalMeta = std::nullopt,
        .dio = entryDIO
    };
    auto encryptedEntryData = _entryDataEncryptorV5.encrypt(entryData, _userPrivKey, msgKey.key);
    send_entry_model.kvdbEntryValue(encryptedEntryData.asVar());
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, sendEntry, data encrypted)
    _serverApi.kvdbEntrySet(send_entry_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, sendEntry, data send)
}

void KvdbApiImpl::deleteEntry(const std::string& kvdbId, const std::string& key) {
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbEntryDeleteModel>();
    model.kvdbId(kvdbId);
    model.kvdbEntryKey(key);
    _serverApi.kvdbEntryDelete(model);
}

std::map<std::string, bool> KvdbApiImpl::deleteEntries(const std::string& kvdbId, const std::vector<std::string>& keys) {
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbEntryDeleteManyModel>();
    model.kvdbId(kvdbId);
    model.kvdbEntryKeys(utils::TypedObjectFactory::createNewList<std::string>());
    for(auto key : keys) {
        model.kvdbEntryKeys().add(key);
    }
    auto deleteStatuses = _serverApi.kvdbEntryDeleteMany(model).results();
    std::map<std::string, bool> result;
    for(auto deleteStatus : deleteStatuses) {
        result.insert(std::make_pair(deleteStatus.kvdbEntryKey(), deleteStatus.status() == "OK"));
    }
    return result;
}

void KvdbApiImpl::processNotificationEvent(const std::string& type, const core::NotificationEvent& notification) {
    if(!_kvdbSubscriptionHelper.hasSubscription(notification.subscriptions) && notification.source != core::EventSource::INTERNAL) {
        return;
    }
    if (type == "kvdbCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbInfo>(notification.data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.updateByValue(raw);
            auto statusCode = validateKvdbDataIntegrity(raw);
            privmx::endpoint::kvdb::Kvdb data;
            if(statusCode == 0) {
                data = decryptAndConvertKvdbDataToKvdb(raw); 
            } else {
                data = Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode, {}};
            }
            std::shared_ptr<KvdbCreatedEvent> event(new KvdbCreatedEvent());
            event->channel = "kvdb";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbInfo>(notification.data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.updateByValue(raw);
            auto statusCode = validateKvdbDataIntegrity(raw);
            privmx::endpoint::kvdb::Kvdb data;
            if(statusCode == 0) {
                data = decryptAndConvertKvdbDataToKvdb(raw); 
            } else {
                data = Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode, {}};
            }
            std::shared_ptr<KvdbUpdatedEvent> event(new KvdbUpdatedEvent());
            event->channel = "kvdb";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbDeleted") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbDeletedEventData>(notification.data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.invalidateByContainerId(raw.kvdbId());
            auto data = Mapper::mapToKvdbDeletedEventData(raw);
            std::shared_ptr<KvdbDeletedEvent> event(new KvdbDeletedEvent());
            event->channel = "kvdb";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbStats") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbStatsEventData>(notification.data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.updateStats(raw);
            auto data = Mapper::mapToKvdbStatsEventData(raw);
            std::shared_ptr<KvdbStatsChangedEvent> event(new KvdbStatsChangedEvent());
            event->channel = "kvdb";
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbNewEntry") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbEntryInfo>(notification.data);
        auto data = decryptAndConvertEntryDataToEntry(raw);
        std::shared_ptr<KvdbNewEntryEvent> event(new KvdbNewEntryEvent());
        event->channel = "kvdb/" + raw.kvdbId() + "/entries";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "kvdbUpdatedEntry") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbEntryInfo>(notification.data);
        auto data = decryptAndConvertEntryDataToEntry(raw);
        std::shared_ptr<KvdbEntryUpdatedEvent> event(new KvdbEntryUpdatedEvent());
        event->channel = "kvdb/" + raw.kvdbId() + "/entries";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "kvdbDeletedEntry") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbDeletedEntryEventData>(notification.data);
        auto data = Mapper::mapToKvdbDeletedEntryEventData(raw);
        std::shared_ptr<KvdbEntryDeletedEvent> event(new KvdbEntryDeletedEvent());
        event->channel = "kvdb/" + raw.kvdbId() + "/entries";
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "subscribe") {
        Poco::JSON::Object::Ptr data = notification.data.extract<Poco::JSON::Object::Ptr>();
        std::string channelName = data->has("channel") ? data->getValue<std::string>("channel") : "";
        if(channelName == "kvdb") {
            PRIVMX_DEBUG("KvdbApi", "Cache", "Enabled")
            _subscribeForKvdb = true;
        }
    } else if (type == "unsubscribe") {
        Poco::JSON::Object::Ptr data = notification.data.extract<Poco::JSON::Object::Ptr>();
        std::string channelName = data->has("channel") ?  data->getValue<std::string>("channel") : "";
        if(channelName == "kvdb") {
            PRIVMX_DEBUG("KvdbApi", "Cache", "Disabled")
            _subscribeForKvdb = false;
            _kvdbProvider.invalidate();
        }
    }
}

void KvdbApiImpl::subscribeForKvdbEvents() {
    if(_kvdbSubscriptionHelper.hasSubscriptionForModule()) {
        throw AlreadySubscribedException();
    }
    _kvdbSubscriptionHelper.subscribeForModule();
}

void KvdbApiImpl::unsubscribeFromKvdbEvents() {
    if(!_kvdbSubscriptionHelper.hasSubscriptionForModule()) {
        throw NotSubscribedException();
    }
    _kvdbSubscriptionHelper.unsubscribeFromModule();
}

void KvdbApiImpl::subscribeForEntryEvents(std::string kvdbId) {
    assertKvdbExist(kvdbId);
    if(_kvdbSubscriptionHelper.hasSubscriptionForModuleEntry(kvdbId)) {
        throw AlreadySubscribedException(kvdbId);
    }
    _kvdbSubscriptionHelper.subscribeForModuleEntry(kvdbId);
}

void KvdbApiImpl::unsubscribeFromEntryEvents(std::string kvdbId) {
    assertKvdbExist(kvdbId);
    if(!_kvdbSubscriptionHelper.hasSubscriptionForModuleEntry(kvdbId)) {
        throw NotSubscribedException(kvdbId);
    }
    _kvdbSubscriptionHelper.unsubscribeFromModuleEntry(kvdbId);
}

void KvdbApiImpl::processConnectedEvent() {
    _kvdbProvider.invalidate();
}

void KvdbApiImpl::processDisconnectedEvent() {
    _kvdbProvider.invalidate();
}

privmx::utils::List<std::string> KvdbApiImpl::mapUsers(const std::vector<core::UserWithPubKey>& users) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user : users) {
        result.add(user.userId);
    }
    return result;
}

DecryptedKvdbDataV5 KvdbApiImpl::decryptKvdbV5(server::KvdbDataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedKvdbData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKvdbDataV5>(kvdbEntry.data());
        if(encKey.statusCode != 0) {
            auto tmp = _kvdbDataEncryptorV5.extractPublic(encryptedKvdbData);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _kvdbDataEncryptorV5.decrypt(encryptedKvdbData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedKvdbDataV5{{.dataStructureVersion = KvdbDataSchema::Version::VERSION_5, .statusCode = e.getCode()}, {},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedKvdbDataV5{{.dataStructureVersion = KvdbDataSchema::Version::VERSION_5, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{}};
    } catch (...) {
        return DecryptedKvdbDataV5{{.dataStructureVersion = KvdbDataSchema::Version::VERSION_5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{}};
    }
}

Kvdb KvdbApiImpl::convertDecryptedKvdbDataV5ToKvdb(server::KvdbInfo kvdbInfo, const DecryptedKvdbDataV5& kvdbData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : kvdbInfo.users()) {
        users.push_back(x);
    }
    for (auto x : kvdbInfo.managers()) {
        managers.push_back(x);
    }

    return {
        .contextId = kvdbInfo.contextId(),
        .kvdbId = kvdbInfo.id(),
        .createDate = kvdbInfo.createDate(),
        .creator = kvdbInfo.creator(),
        .lastModificationDate = kvdbInfo.lastModificationDate(),
        .lastModifier = kvdbInfo.lastModifier(),
        .users = users,
        .managers = managers,
        .version = kvdbInfo.version(),
        .publicMeta = kvdbData.publicMeta,
        .privateMeta = kvdbData.privateMeta,
        .entries = kvdbInfo.entries(),
        .lastEntryDate = kvdbInfo.lastEntryDate(),
        .policy = core::Factory::parsePolicyServerObject(kvdbInfo.policy()), 
        .statusCode = kvdbData.statusCode,
        .schemaVersion = KvdbDataSchema::Version::VERSION_5
    };
}

KvdbDataSchema::Version KvdbApiImpl::getKvdbDataEntryStructureVersion(server::KvdbDataEntry kvdbEntry) {
    if (kvdbEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(kvdbEntry.data());
        auto version = versioned.versionOpt(KvdbDataSchema::Version::UNKNOWN);
        switch (version) {
            case KvdbDataSchema::Version::VERSION_5:
                return KvdbDataSchema::Version::VERSION_5;
            default:
                return KvdbDataSchema::Version::UNKNOWN;
        }
    }
    return KvdbDataSchema::Version::UNKNOWN;
}

std::tuple<Kvdb, core::DataIntegrityObject> KvdbApiImpl::decryptAndConvertKvdbDataToKvdb(server::KvdbInfo kvdb, server::KvdbDataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    switch (getKvdbDataEntryStructureVersion(kvdbEntry)) {
        case KvdbDataSchema::Version::UNKNOWN: {
            auto e = UnknownKvdbFormatException();
            return std::make_tuple(Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode(), {}}, core::DataIntegrityObject());
        }
        case KvdbDataSchema::Version::VERSION_5: {
            auto decryptedKvdbData = decryptKvdbV5(kvdbEntry, encKey);
            return std::make_tuple(convertDecryptedKvdbDataV5ToKvdb(kvdb, decryptedKvdbData), decryptedKvdbData.dio);
        }
    }    
    auto e = UnknownKvdbFormatException();
    return std::make_tuple(Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode(), {}}, core::DataIntegrityObject());
}


std::vector<Kvdb> KvdbApiImpl::decryptAndConvertKvdbsDataToKvdbs(privmx::utils::List<server::KvdbInfo> kvdbs) {
    std::vector<Kvdb> result;
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    //create request to KeyProvider for keys
    for (size_t i = 0; i < kvdbs.size(); i++) {
        auto kvdb = kvdbs.get(i);
        core::EncKeyLocation location{.contextId=kvdb.contextId(), .resourceId=kvdb.resourceId()};
        auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
        keyProviderRequest.addOne(kvdb.keys(), kvdb_data_entry.keyId(), location);
    }
    //send request to KeyProvider
    auto kvdbKeys {_keyProvider->getKeysAndVerify(keyProviderRequest)};
    std::vector<core::DataIntegrityObject> kvdbsDIO;
    std::map<std::string, bool> duplication_check;
    for (size_t i = 0; i < kvdbs.size(); i++) {
        auto kvdb = kvdbs.get(i);
        try {
            auto tmp = decryptAndConvertKvdbDataToKvdb(
                kvdb, 
                kvdb.data().get(kvdb.data().size()-1), 
                kvdbKeys.at({.contextId=kvdb.contextId(), .resourceId=kvdb.resourceId()}).at(kvdb.data().get(kvdb.data().size()-1).keyId())
            );
            result.push_back(std::get<0>(tmp));
            auto kvdbDIO = std::get<1>(tmp);
            kvdbsDIO.push_back(kvdbDIO);
            //find duplication
            std::string fullRandomId = kvdbDIO.randomId + "-" + std::to_string(kvdbDIO.timestamp);
            if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                duplication_check.insert(std::make_pair(fullRandomId, true));
            } else {
                result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result.push_back(Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode(), {}});
            kvdbsDIO.push_back(core::DataIntegrityObject{});
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back(core::VerificationRequest{
                .contextId = result[i].contextId,
                .senderId = result[i].lastModifier,
                .senderPubKey = kvdbsDIO[i].creatorPubKey,
                .date = result[i].lastModificationDate,
                .bridgeIdentity = kvdbsDIO[i].bridgeIdentity
            });
        }
    }
    std::vector<bool> verified;
    try {
        verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    for (size_t j = 0, i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            result[i].statusCode = verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
            j++;
        }
    }
    return result;
}

Kvdb KvdbApiImpl::decryptAndConvertKvdbDataToKvdb(server::KvdbInfo kvdb) {
    auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=kvdb.contextId(), .resourceId=kvdb.resourceId()};
    keyProviderRequest.addOne(kvdb.keys(), kvdb_data_entry.keyId(), location);
    auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(kvdb_data_entry.keyId());
    Kvdb result;
    core::DataIntegrityObject kvdbDIO;
    std::tie(result, kvdbDIO) = decryptAndConvertKvdbDataToKvdb(kvdb, kvdb_data_entry, encKey);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
    verifierInput.push_back(core::VerificationRequest{
        .contextId = result.contextId,
        .senderId = result.lastModifier,
        .senderPubKey = kvdbDIO.creatorPubKey,
        .date = result.lastModificationDate,
        .bridgeIdentity = kvdbDIO.bridgeIdentity
    });
    std::vector<bool> verified;
    try {
        verified =_connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    return result;
}


DecryptedKvdbEntryDataV5 KvdbApiImpl::decryptKvdbEntryDataV5(server::KvdbEntryInfo entry, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedEntryData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKvdbEntryDataV5>(entry.kvdbEntryValue());
        if(encKey.statusCode != 0) {
            auto tmp = _entryDataEncryptorV5.extractPublic(encryptedEntryData);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _entryDataEncryptorV5.decrypt(encryptedEntryData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedKvdbEntryDataV5{{.dataStructureVersion = KvdbEntryDataSchema::Version::VERSION_5, .statusCode = e.getCode()}, {},{},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedKvdbEntryDataV5{{.dataStructureVersion = KvdbEntryDataSchema::Version::VERSION_5, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{},{}};
    } catch (...) {
        return DecryptedKvdbEntryDataV5{{.dataStructureVersion = KvdbEntryDataSchema::Version::VERSION_5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{},{}};
    }
}

KvdbEntry KvdbApiImpl::convertDecryptedKvdbEntryDataV5ToKvdbEntry(server::KvdbEntryInfo entry, DecryptedKvdbEntryDataV5 entryData) {
    KvdbEntry ret {
        .info = {
            .kvdbId = entry.kvdbId(),
            .key = entry.kvdbEntryKey(),
            .createDate = entry.createDate(),
            .author = entry.author(),
        },
        .publicMeta = entryData.publicMeta, 
        .privateMeta = entryData.privateMeta,
        .data = entryData.data,
        .authorPubKey = entryData.authorPubKey,
        .version = entry.version(),
        .statusCode = entryData.statusCode,
        .schemaVersion = KvdbEntryDataSchema::Version::VERSION_5
    };
    return ret;
}


KvdbEntryDataSchema::Version KvdbApiImpl::getMessagesDataStructureVersion(server::KvdbEntryInfo entry) {
    if (entry.kvdbEntryValue().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::dynamic::VersionedData>(entry.kvdbEntryValue());
        auto version = versioned.versionOpt(KvdbEntryDataSchema::Version::UNKNOWN);
        switch (version) {
            case KvdbEntryDataSchema::Version::VERSION_5:
                return KvdbEntryDataSchema::Version::VERSION_5;
            default:
                return KvdbEntryDataSchema::Version::UNKNOWN;
        }
    }
    return KvdbEntryDataSchema::Version::UNKNOWN;
}

std::tuple<KvdbEntry, core::DataIntegrityObject> KvdbApiImpl::decryptAndConvertEntryDataToEntry(server::KvdbEntryInfo entry, const core::DecryptedEncKey& encKey) {
    switch (getMessagesDataStructureVersion(entry)) {
        case KvdbEntryDataSchema::Version::UNKNOWN: {
            auto e = UnknownKvdbEntryFormatException();
            return std::make_tuple(KvdbEntry{{},{},{},{},{},{},.statusCode = e.getCode(), {}}, core::DataIntegrityObject());
        }
        case KvdbEntryDataSchema::Version::VERSION_5: {
            auto decryptEntry = decryptKvdbEntryDataV5(entry, encKey);
            return std::make_tuple(convertDecryptedKvdbEntryDataV5ToKvdbEntry(entry, decryptEntry), decryptEntry.dio);
        }
    }
    auto e = UnknownKvdbEntryFormatException();
    return std::make_tuple(KvdbEntry{{},{},{},{},{},{},.statusCode = e.getCode(), {}}, core::DataIntegrityObject());
}

std::vector<KvdbEntry> KvdbApiImpl::decryptAndConvertKvdbEntriesDataToKvdbEntries(server::KvdbInfo kvdb, utils::List<server::KvdbEntryInfo> entries) {
   std::set<std::string> keyIds;
    for (auto entry : entries) {
        keyIds.insert(entry.keyId());
    }
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=kvdb.contextId(), .resourceId=kvdb.resourceId()};
    keyProviderRequest.addMany(kvdb.keys(), keyIds, location);
    auto keyMap = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location);
    std::vector<KvdbEntry> result;
    std::vector<core::DataIntegrityObject> entriesDIO;
    std::map<std::string, bool> duplication_check;
    for (auto entry : entries) {
        try {
            auto statusCode = validateEntryDataIntegrity(entry, kvdb.resourceId());
            if(statusCode == 0) {
                auto tmp = decryptAndConvertEntryDataToEntry(entry, keyMap.at(entry.keyId()));
                result.push_back(std::get<0>(tmp));
                auto entryDIO = std::get<1>(tmp);
                entriesDIO.push_back(entryDIO);
                //find duplication
                std::string fullRandomId = entryDIO.randomId + "-" + std::to_string(entryDIO.timestamp);
                if(duplication_check.find(fullRandomId) == duplication_check.end()) {
                    duplication_check.insert(std::make_pair(fullRandomId, true));
                } else {
                    result[result.size()-1].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
                }
            } else {
                result.push_back(KvdbEntry{{},{},{},{},{},{},.statusCode = statusCode, {}});
            }
        } catch (const core::Exception& e) {
            result.push_back(KvdbEntry{{},{},{},{},{},{},.statusCode = e.getCode(), {}});
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back(core::VerificationRequest{
                .contextId = kvdb.contextId(),
                .senderId = result[i].info.author,
                .senderPubKey = result[i].authorPubKey,
                .date = result[i].info.createDate,
                .bridgeIdentity = entriesDIO[i].bridgeIdentity
            });
        }
    }
    std::vector<bool> verified;
    try {
        verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    for (size_t j = 0, i = 0; i < result.size(); ++i) {
        if (result[i].statusCode == 0) {
            result[i].statusCode = verified[j] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
            j++;
        }
    }
    return result;
}

KvdbEntry KvdbApiImpl::decryptAndConvertEntryDataToEntry(server::KvdbInfo kvdb, server::KvdbEntryInfo entry) {
    auto keyId = entry.keyId();
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=kvdb.contextId(), .resourceId=kvdb.resourceId()};
    keyProviderRequest.addOne(kvdb.keys(), keyId, location);
    auto encKey = _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(keyId);
    KvdbEntry result;
    core::DataIntegrityObject entryDIO;
    std::tie(result, entryDIO) = decryptAndConvertEntryDataToEntry(entry, encKey);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
        verifierInput.push_back(core::VerificationRequest{
            .contextId = kvdb.contextId(),
            .senderId = result.info.author,
            .senderPubKey = result.authorPubKey,
            .date = result.info.createDate,
            .bridgeIdentity = entryDIO.bridgeIdentity
        });
    std::vector<bool> verified;
    try {
        verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
    } catch (...) {
        throw core::UserVerificationMethodUnhandledException();
    }
    result.statusCode = verified[0] ? 0 : core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    return result;
}

KvdbEntry KvdbApiImpl::decryptAndConvertEntryDataToEntry(server::KvdbEntryInfo entry) {
    try {
        auto kvdb = getRawKvdbFromCacheOrBridge(entry.kvdbId());
        return decryptAndConvertEntryDataToEntry(kvdb, entry);
    } catch (const core::Exception& e) {
        return KvdbEntry{{},{},{},{},{},{},.statusCode = e.getCode(), {}};
    } catch (const privmx::utils::PrivmxException& e) {
        return KvdbEntry{{},{},{},{},{},{},.statusCode = e.getCode(), {}};
    } catch (...) {
        return KvdbEntry{{},{},{},{},{},{},.statusCode = ENDPOINT_CORE_EXCEPTION_CODE, {}};
    }
}

KvdbInternalMetaV5 KvdbApiImpl::decryptKvdbInternalMeta(server::KvdbDataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    switch (getKvdbDataEntryStructureVersion(kvdbEntry)) {
        case KvdbDataSchema::Version::UNKNOWN:
            throw UnknownKvdbFormatException();
        case KvdbDataSchema::Version::VERSION_5:
            return decryptKvdbV5(kvdbEntry, encKey).internalMeta;
    }
    throw UnknownKvdbFormatException();
}

core::DecryptedEncKey KvdbApiImpl::getKvdbCurrentEncKey(server::KvdbInfo kvdb) {
    auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId=kvdb.contextId(), .resourceId=kvdb.resourceId()};
    keyProviderRequest.addOne(kvdb.keys(), kvdb_data_entry.keyId(), location);
    return _keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(kvdb_data_entry.keyId());
}

server::KvdbInfo KvdbApiImpl::getRawKvdbFromCacheOrBridge(const std::string& kvdbId) {
    // useing kvdbProvider only with KVDB_TYPE_FILTER_FLAG 
    // making sure to have valid cache
    if(!_subscribeForKvdb) _kvdbProvider.update(kvdbId);
    auto kvdbContainerInfo = _kvdbProvider.get(kvdbId);
    if(kvdbContainerInfo.status != core::DataIntegrityStatus::ValidationSucceed) {
        throw KvdbDataIntegrityException();
    }
    return kvdbContainerInfo.container;
}

void KvdbApiImpl::assertKvdbExist(const std::string& kvdbId) {
    //check if kvdb is in cache or on server
    getRawKvdbFromCacheOrBridge(kvdbId);
}

uint32_t KvdbApiImpl::validateKvdbDataIntegrity(server::KvdbInfo kvdb) {
    auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
    try {
        switch (getKvdbDataEntryStructureVersion(kvdb_data_entry)) {
            case KvdbDataSchema::Version::UNKNOWN:
                return UnknownKvdbFormatException().getCode();
            case KvdbDataSchema::Version::VERSION_5: {
                auto kvdb_data = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKvdbDataV5>(kvdb_data_entry.data());
                auto dio = _kvdbDataEncryptorV5.getDIOAndAssertIntegrity(kvdb_data);
                if(
                    dio.contextId != kvdb.contextId() ||
                    dio.resourceId != kvdb.resourceIdOpt("") ||
                    dio.creatorUserId != kvdb.lastModifier() ||
                    !core::TimestampValidator::validate(dio.timestamp, kvdb.lastModificationDate())
                ) {
                    return KvdbDataIntegrityException().getCode();
                }
                return 0;
            }
        }
    } catch (const core::Exception& e) {
        return e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        return e.getCode();
    } catch (...) {
        return ENDPOINT_CORE_EXCEPTION_CODE;
    } 
    return UnknownKvdbFormatException().getCode();
}

uint32_t KvdbApiImpl::validateEntryDataIntegrity(server::KvdbEntryInfo entry, const std::string& kvdbResourceId) {
    try {
        switch (getMessagesDataStructureVersion(entry)) {
            case KvdbEntryDataSchema::Version::UNKNOWN:
                return UnknownKvdbEntryFormatException().getCode();
            case KvdbEntryDataSchema::Version::VERSION_5: {
                auto encData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKvdbEntryDataV5>(entry.kvdbEntryValue());
                auto dio = _entryDataEncryptorV5.getDIOAndAssertIntegrity(encData);
                if(
                    dio.contextId != entry.contextId() ||
                    dio.resourceId != entry.kvdbEntryKey() ||
                    !dio.containerId.has_value() || dio.containerId.value() != entry.kvdbId() ||
                    !dio.containerResourceId.has_value() || dio.containerResourceId.value() != kvdbResourceId ||
                    dio.creatorUserId != entry.lastModifier() ||
                    !core::TimestampValidator::validate(dio.timestamp, entry.lastModificationDate())
                ) {
                    return KvdbEntryDataIntegrityException().getCode();
                }
                return 0;
            }
        }
    } catch (const core::Exception& e) {
    return e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        return e.getCode();
    } catch (...) {
        return ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return UnknownKvdbEntryFormatException().getCode();
}


