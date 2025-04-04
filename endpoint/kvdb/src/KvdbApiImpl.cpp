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
    _kvdbSubscriptionHelper(core::SubscriptionHelper(eventChannelManager, "kvdb", "items"))
{
    _notificationListenerId = _eventMiddleware->addNotificationEventListener(std::bind(&KvdbApiImpl::processNotificationEvent, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
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
    auto kvdbDIO = _connection.getImpl()->createDIO(
        contextId,
        utils::Utils::getNowTimestampStr() + "-" + utils::Hex::from(crypto::Crypto::randomBytes(8))
    );
    auto kvdbCCN = _keyProvider->generateContainerControlNumber();
    KvdbDataToEncryptV5 kvdbDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::Buffer::from(std::to_string(kvdbCCN)),
        .dio = kvdbDIO
    };
    auto create_kvdb_model = utils::TypedObjectFactory::createNewObject<server::KvdbCreateModel>();
    create_kvdb_model.kvdbId(kvdbDIO.containerId);
    create_kvdb_model.contextId(contextId);
    create_kvdb_model.keyId(kvdbKey.id);
    create_kvdb_model.data(_kvdbDataEncryptorV5.encrypt(kvdbDataToEncrypt, _userPrivKey, kvdbKey.key).asVar());
    auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    create_kvdb_model.keys(
        _keyProvider->prepareKeysList(
            allUsers, 
            kvdbKey, 
            kvdbDIO,
            kvdbCCN
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
    auto kvdbKeys {_keyProvider->getAllKeysAndVerify(currentKvdb.keys(), {.contextId=currentKvdb.contextId(), .containerId=kvdbId})};
    auto currentKvdbEntry = currentKvdb.data().get(currentKvdb.data().size()-1);
    core::DecryptedEncKey currentKvdbKey;
    for (auto key : kvdbKeys) {
        if (currentKvdbEntry.keyId() == key.id) {
            currentKvdbKey = key;
            break;
        }
    }
    auto kvdbCCN = decryptKvdbInternalMeta(currentKvdbEntry, currentKvdbKey);
    for(auto key : kvdbKeys) {
        if(key.statusCode != 0 || (key.dataStructureVersion == 2 && key.containerControlNumber != kvdbCCN)) {
            throw KvdbEncryptionKeyValidationException();
        }
    }
    // setting kvdb Key adding new users
    core::EncKey kvdbKey;
    core::DataIntegrityObject updateKvdbDio = _connection.getImpl()->createDIO(currentKvdb.contextId(), kvdbId);
    privmx::utils::List<core::server::KeyEntrySet> keys = utils::TypedObjectFactory::createNewList<core::server::KeyEntrySet>();
    if(needNewKey) {
        kvdbKey = _keyProvider->generateKey();
        keys = _keyProvider->prepareKeysList(
            new_users, 
            kvdbKey, 
            updateKvdbDio,
            kvdbCCN
        );
    } else {
        // find key with corresponding keyId 
        for(size_t i = 0; i < kvdbKeys.size(); i++) {
            kvdbKey = kvdbKeys[i];
        }
    }
    if(usersToAddMissingKey.size() > 0) {
        auto tmp = _keyProvider->prepareMissingKeysForNewUsers(
            kvdbKeys,
            usersToAddMissingKey, 
            updateKvdbDio, 
            kvdbKeys[0].containerControlNumber
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

    model.kvdbId(kvdbId);
    model.keyId(kvdbKey.id);
    model.keys(keys);
    model.users(usersList);
    model.managers(managersList);
    model.version(version);
    model.force(force);
    if (policies.has_value()) {
        model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    auto kvdbDIO = _connection.getImpl()->createDIO(
        currentKvdb.contextId(),
        kvdbId
    );
    KvdbDataToEncryptV5 kvdbDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = core::Buffer::from(std::to_string(kvdbCCN)),
        .dio = kvdbDIO
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
        if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateDataIntegrityStatus(kvdbId, core::DataIntegrityStatus::ValidationFailed);
        return Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode};
    } else {
        if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateDataIntegrityStatus(kvdbId, core::DataIntegrityStatus::ValidationSucceed);
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
        kvdbs.push_back(Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode});
        if(statusCode == 0) {
            if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateDataIntegrityStatus(kvdb.id() ,core::DataIntegrityStatus::ValidationSucceed);
        } else {
            if(type == KVDB_TYPE_FILTER_FLAG) _kvdbProvider.updateDataIntegrityStatus(kvdb.id() ,core::DataIntegrityStatus::ValidationFailed);
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

Item KvdbApiImpl::getItem(const std::string& kvdbId, const std::string& key) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, getItem)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbItemGetModel>();
    model.kvdbId(kvdbId);
    model.kvdbItemKey(key);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getItem, getting item)
    auto item = _serverApi.kvdbItemGet(model).kvdbItem();
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getItem, data recived);
    privmx::endpoint::kvdb::server::KvdbInfo kvdb;
    Item result;
    try {
        PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getItem, getting kvdb)
        kvdb = getRawKvdbFromCacheOrBridge(kvdbId);
        PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, getItem, decrypting item)
        auto statusCode = validateItemDataIntegrity(item);
        if(statusCode != 0) {
            PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, getItem, data integrity validation failed)
            result.statusCode = statusCode;
            return result;
        }
        result = decryptAndConvertItemDataToItem(kvdb, item);
    } catch (const core::Exception& e) {
        PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, getItem, data decrypted failed)
        result.statusCode = e.getCode();
        return result;
    }
    if (result.statusCode == 0) {
        std::vector<core::VerificationRequest> verifierInput {{
            .contextId = kvdb.contextId(),
            .senderId = result.info.author,
            .senderPubKey = result.authorPubKey,
            .date = result.info.createDate
        }};

        std::vector<bool> verified;
        try {
            verified = _connection.getImpl()->getUserVerifier()->verify(verifierInput);
        } catch (...) {
            throw core::UserVerificationMethodUnhandledException();
        }
        if (verified[0] == false) {
            result.statusCode = core::ExceptionConverter::getCodeOfUserVerificationFailureException();
        }
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, getItem, data decrypted)
    return result;
}

core::PagingList<std::string> KvdbApiImpl::listItemKeys(const std::string& kvdbId, const kvdb::KeysPagingQuery& pagingQuery) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, listItemKeys)
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbListKeysModel>();
    model.kvdbId(kvdbId);
    kvdb::Mapper::map(model, pagingQuery);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listItemKeys, getting itemList)
    auto itemsList = _serverApi.kvdbListKeys(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, listItemKeys, data send)
    std::vector<std::string> keys;
    for(auto key : itemsList.kvdbItemKeys()) {
        keys.push_back(key);
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, listItemKeys, data decrypted)
    return core::PagingList<std::string>({
        .totalAvailable = itemsList.count(),
        .readItems = keys
    });
}


std::string KvdbApiImpl::sendItem(const std::string& kvdbId, const core::Buffer& publicMeta, const core::Buffer& privateMeta, const core::Buffer& data) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, sendItem);
    auto kvdb = getRawKvdbFromCacheOrBridge(kvdbId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, sendItem, getKvdb)
    auto msgKey = getKvdbCurrentEncKey(kvdb);
    auto  send_item_model = utils::TypedObjectFactory::createNewObject<server::KvdbItemSendModel>();
    send_item_model.kvdbId(kvdb.id());
    send_item_model.keyId(msgKey.id);
    auto itemDIO = _connection.getImpl()->createDIO(
        kvdb.contextId(),
        kvdbId
    );
    ItemDataToEncryptV5 itemData {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .data = data,
        .internalMeta = std::nullopt,
        .dio = itemDIO
    };
    auto encryptedItemData = _itemDataEncryptorV5.encrypt(itemData, _userPrivKey, msgKey.key);
    send_item_model.data(encryptedItemData.asVar());
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, sendItem, data encrypted)
    auto result = _serverApi.kvdbItemSend(send_item_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, sendItem, data send)
    return result.itemId();
}
void KvdbApiImpl::deleteItem(const std::string& itemId) {
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbItemDeleteModel>();
    model.itemId(itemId);
    _serverApi.kvdbItemDelete(model);
}
void KvdbApiImpl::updateItem(
    const std::string& itemId, 
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const core::Buffer& data
) {
    PRIVMX_DEBUG_TIME_START(PlatformKvdb, updateItem);
    auto model = utils::TypedObjectFactory::createNewObject<server::KvdbItemGetModel>();
    model.itemId(itemId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, updateItem, getting item)
    auto item = _serverApi.kvdbItemGet(model).item();
    auto statusCode = validateItemDataIntegrity(item);
    if(statusCode != 0) {
        throw ItemDataIntegrityException();
    }
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, updateItem, getting kvdb)

    auto kvdb = getRawKvdbFromCacheOrBridge(item.kvdbId());

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, updateItem, data preparing)
    auto msgKey = getKvdbCurrentEncKey(kvdb);
    auto  send_item_model = utils::TypedObjectFactory::createNewObject<server::KvdbItemUpdateModel>();
    send_item_model.itemId(itemId);
    send_item_model.keyId(msgKey.id);
    auto itemDIO = _connection.getImpl()->createDIO(
        item.contextId(),
        item.kvdbId()
    );
    ItemDataToEncryptV5 itemData {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .data = data,
        .internalMeta = std::nullopt,
        .dio = itemDIO
    };
    auto encryptedItemData = _itemDataEncryptorV5.encrypt(itemData, _userPrivKey, msgKey.key);
    send_item_model.data(encryptedItemData.asVar());
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformKvdb, updateItem, data encrypted)
    _serverApi.kvdbItemUpdate(send_item_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformKvdb, updateItem, data send)
}

void KvdbApiImpl::processNotificationEvent(const std::string& type, const std::string& channel, const Poco::JSON::Object::Ptr& data) {
    if(!_kvdbSubscriptionHelper.hasSubscriptionForChannel(channel) && channel != INTERNAL_EVENT_CHANNEL_NAME) {
        return;
    }
    if (type == "kvdbCreated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbInfo>(data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.updateByValue(raw);
            auto statusCode = validateKvdbDataIntegrity(raw);
            privmx::endpoint::kvdb::Kvdb data;
            if(statusCode == 0) {
                data = decryptAndConvertKvdbDataToKvdb(raw); 
            } else {
                data = Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode};
            }
            std::shared_ptr<KvdbCreatedEvent> event(new KvdbCreatedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbUpdated") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbInfo>(data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.updateByValue(raw);
            auto statusCode = validateKvdbDataIntegrity(raw);
            privmx::endpoint::kvdb::Kvdb data;
            if(statusCode == 0) {
                data = decryptAndConvertKvdbDataToKvdb(raw); 
            } else {
                data = Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = statusCode};
            }
            std::shared_ptr<KvdbUpdatedEvent> event(new KvdbUpdatedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbDeleted") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbDeletedEventData>(data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.invalidateByContainerId(raw.kvdbId());
            auto data = Mapper::mapToKvdbDeletedEventData(raw);
            std::shared_ptr<KvdbDeletedEvent> event(new KvdbDeletedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbStats") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbStatsEventData>(data);
        if(raw.typeOpt(std::string(KVDB_TYPE_FILTER_FLAG)) == KVDB_TYPE_FILTER_FLAG) {
            _kvdbProvider.updateStats(raw);
            auto data = Mapper::mapToKvdbStatsEventData(raw);
            std::shared_ptr<KvdbStatsChangedEvent> event(new KvdbStatsChangedEvent());
            event->channel = channel;
            event->data = data;
            _eventMiddleware->emitApiEvent(event);
        }
    } else if (type == "kvdbNewItem") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::Item>(data);
        auto data = decryptAndConvertItemDataToItem(raw);
        std::shared_ptr<KvdbNewItemEvent> event(new KvdbNewItemEvent());
        event->channel = channel;
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "kvdbUpdatedItem") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::Item>(data);
        auto data = decryptAndConvertItemDataToItem(raw);
        std::shared_ptr<KvdbItemUpdatedEvent> event(new KvdbItemUpdatedEvent());
        event->channel = channel;
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "kvdbDeletedItem") {
        auto raw = utils::TypedObjectFactory::createObjectFromVar<server::KvdbDeletedItemEventData>(data);
        auto data = Mapper::mapToKvdbDeletedItemEventData(raw);
        std::shared_ptr<KvdbItemDeletedEvent> event(new KvdbItemDeletedEvent());
        event->channel = channel;
        event->data = data;
        _eventMiddleware->emitApiEvent(event);
    } else if (type == "subscribe") {
        std::string channelName = data->has("channel") ? data->getValue<std::string>("channel") : "";
        if(channelName == "kvdb") {
            PRIVMX_DEBUG("KvdbApi", "Cache", "Enabled")
            _subscribeForKvdb = true;
        }
    } else if (type == "unsubscribe") {
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

void KvdbApiImpl::subscribeForItemEvents(std::string kvdbId) {
    assertKvdbExist(kvdbId);
    if(_kvdbSubscriptionHelper.hasSubscriptionForElement(kvdbId)) {
        throw AlreadySubscribedException(kvdbId);
    }
    _kvdbSubscriptionHelper.subscribeForElement(kvdbId);
}

void KvdbApiImpl::unsubscribeFromItemEvents(std::string kvdbId) {
    assertKvdbExist(kvdbId);
    if(!_kvdbSubscriptionHelper.hasSubscriptionForElement(kvdbId)) {
        throw NotSubscribedException(kvdbId);
    }
    _kvdbSubscriptionHelper.unsubscribeFromElement(kvdbId);
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

dynamic::KvdbDataV1 KvdbApiImpl::decryptKvdbV1(server::Kvdb2DataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    try {
        return _dataEncryptorKvdb.decrypt(kvdbEntry.data(), encKey);
    } catch (const core::Exception& e) {
        dynamic::KvdbDataV1 result = utils::TypedObjectFactory::createNewObject<dynamic::KvdbDataV1>();
        result.title(std::string());
        result.statusCode(e.getCode());
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        dynamic::KvdbDataV1 result = utils::TypedObjectFactory::createNewObject<dynamic::KvdbDataV1>();
        result.title(std::string());
        result.statusCode(core::ExceptionConverter::convert(e).getCode());
        return result;
    } catch (...) {
        dynamic::KvdbDataV1 result = utils::TypedObjectFactory::createNewObject<dynamic::KvdbDataV1>();
        result.title(std::string());
        result.statusCode(ENDPOINT_CORE_EXCEPTION_CODE);
        return result;
    }
}

DecryptedKvdbDataV4 KvdbApiImpl::decryptKvdbV4(server::Kvdb2DataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedKvdbData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKvdbDataV4>(kvdbEntry.data());
        return _kvdbDataEncryptorV4.decrypt(encryptedKvdbData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedKvdbDataV4{{.dataStructureVersion = 4, .statusCode = e.getCode()}, {},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedKvdbDataV4{{.dataStructureVersion = 4, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{}};
    } catch (...) {
        return DecryptedKvdbDataV4{{.dataStructureVersion = 4, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{}};
    }
}

DecryptedKvdbDataV5 KvdbApiImpl::decryptKvdbV5(server::Kvdb2DataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedKvdbData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKvdbDataV5>(kvdbEntry.data());
        if(encKey.statusCode != 0) {
            auto tmp = _kvdbDataEncryptorV5.extractPublic(encryptedKvdbData);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _kvdbDataEncryptorV5.decrypt(encryptedKvdbData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedKvdbDataV5{{.dataStructureVersion = 5, .statusCode = e.getCode()}, {},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedKvdbDataV5{{.dataStructureVersion = 5, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{}};
    } catch (...) {
        return DecryptedKvdbDataV5{{.dataStructureVersion = 5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{}};
    }
}

Kvdb KvdbApiImpl::convertKvdbDataV1ToKvdb(server::KvdbInfo kvdbInfo, dynamic::KvdbDataV1 kvdbData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : kvdbInfo.users()) {
        users.push_back(x);
    }
    for (auto x : kvdbInfo.managers()) {
        managers.push_back(x);
    }
    Poco::JSON::Object::Ptr privateMeta = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
    privateMeta->set("title", kvdbData.title());
    int64_t statusCode = kvdbData.statusCodeOpt(0);
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
        .lastMsgDate = kvdbInfo.lastMsgDate(),
        .publicMeta = core::Buffer::from(""),
        .privateMeta = core::Buffer::from(utils::Utils::stringify(privateMeta)),
        .policy = {},
        .itemsCount = kvdbInfo.items(),
        .statusCode = statusCode
    };
}

Kvdb KvdbApiImpl::convertDecryptedKvdbDataV4ToKvdb(server::KvdbInfo kvdbInfo, const DecryptedKvdbDataV4& kvdbData) {
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
        .lastMsgDate = kvdbInfo.lastMsgDate(),
        .publicMeta = kvdbData.publicMeta,
        .privateMeta = kvdbData.privateMeta,
        .policy = core::Factory::parsePolicyServerObject(kvdbInfo.policy()), 
        .itemsCount = kvdbInfo.items(),
        .statusCode = kvdbData.statusCode
    };
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
        .lastMsgDate = kvdbInfo.lastMsgDate(),
        .publicMeta = kvdbData.publicMeta,
        .privateMeta = kvdbData.privateMeta,
        .policy = core::Factory::parsePolicyServerObject(kvdbInfo.policy()), 
        .itemsCount = kvdbInfo.items(),
        .statusCode = kvdbData.statusCode
    };
}

std::tuple<Kvdb, std::string> KvdbApiImpl::decryptAndConvertKvdbDataToKvdb(server::KvdbInfo kvdb, server::Kvdb2DataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    if (kvdbEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::server::VersionedData>(kvdbEntry.data());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
                case 4: {
                    auto decryptedKvdbData = decryptKvdbV4(kvdbEntry, encKey);
                    return std::make_tuple(convertDecryptedKvdbDataV4ToKvdb(kvdb, decryptedKvdbData), decryptedKvdbData.authorPubKey);
                }
                case 5: {
                    auto decryptedKvdbData = decryptKvdbV5(kvdbEntry, encKey);
                    return std::make_tuple(convertDecryptedKvdbDataV5ToKvdb(kvdb, decryptedKvdbData), decryptedKvdbData.authorPubKey);
                }
            }
        } 
    } else if (kvdbEntry.data().isString()) {
        return std::make_tuple(convertKvdbDataV1ToKvdb(kvdb, decryptKvdbV1(kvdbEntry, encKey)), "");
    }
    auto e = UnknowKvdbFormatException();
    return std::make_tuple(Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()}, "");
}


std::vector<Kvdb> KvdbApiImpl::decryptAndConvertKvdbsDataToKvdbs(privmx::utils::List<server::KvdbInfo> kvdbs) {
    std::vector<Kvdb> result;
    std::vector<core::DecryptedEncKeyV2> keys;
    //create verification request for keys
    for (size_t i = 0; i < kvdbs.size(); i++) {
        auto kvdb = kvdbs.get(i);
        auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
        auto key = _keyProvider->getKeyAndVerify(kvdb.keys(), kvdb_data_entry.keyId(), {.contextId=kvdb.contextId(), .containerId=kvdb.id(), .enableVerificationRequest=false});
        keys.push_back(key);
    }
    //send verification request and update key statuscode
    _keyProvider->validateUserData(keys);
    //
    std::vector<std::string> lastModifiersPubKey;
    for (size_t i = 0; i < kvdbs.size(); i++) {
        auto kvdb = kvdbs.get(i);
        try {
            auto tmp = decryptAndConvertKvdbDataToKvdb(kvdb, kvdb.data().get(kvdb.data().size()-1), keys[i]);
            result.push_back(std::get<0>(tmp));
            lastModifiersPubKey.push_back(std::get<1>(tmp));
        } catch (const core::Exception& e) {
            result.push_back(Kvdb{ {},{},{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()});
            lastModifiersPubKey.push_back("");

        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (size_t i = 0; i < result.size(); i++) {
        if(result[i].statusCode == 0) {
            verifierInput.push_back({
                .contextId = result[i].contextId,
                .senderId = result[i].lastModifier,
                .senderPubKey = lastModifiersPubKey[i],
                .date = result[i].lastModificationDate
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
    auto key = _keyProvider->getKeyAndVerify(kvdb.keys(), kvdb_data_entry.keyId(), {.contextId=kvdb.contextId(), .containerId=kvdb.id()});
    Kvdb result;
    std::string lastModifierPubKey;
    std::tie(result, lastModifierPubKey) = decryptAndConvertKvdbDataToKvdb(kvdb, kvdb_data_entry, key);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
    verifierInput.push_back({
        .contextId = result.contextId,
        .senderId = result.lastModifier,
        .senderPubKey = lastModifierPubKey,
        .date = result.lastModificationDate
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

dynamic::ItemDataV2 KvdbApiImpl::decryptItemDataV2(server::Item item, const core::DecryptedEncKey& encKey) {
    try {
        auto msg = _itemDataV2Encryptor.decryptAndGetSign(item.data(), encKey);
        return msg.data();
    } catch (const core::Exception& e) {
        dynamic::ItemDataV2 result = utils::TypedObjectFactory::createNewObject<dynamic::ItemDataV2>();
        result.v(0);
        result.statusCode(e.getCode());
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        dynamic::ItemDataV2 result = utils::TypedObjectFactory::createNewObject<dynamic::ItemDataV2>();
        result.v(0);
        result.statusCode(core::ExceptionConverter::convert(e).getCode());
        return result;
    } catch (...) {
        dynamic::ItemDataV2 result = utils::TypedObjectFactory::createNewObject<dynamic::ItemDataV2>();
        result.v(0);
        result.statusCode(ENDPOINT_CORE_EXCEPTION_CODE);
        return result;
    }
    
}

dynamic::ItemDataV3 KvdbApiImpl::decryptItemDataV3(server::Item item, const core::DecryptedEncKey& encKey) {
    try {
        auto msg = _itemDataV3Encryptor.decryptAndGetSign(item.data(), encKey);
        return msg.data();
    } catch (const core::Exception& e) {
        dynamic::ItemDataV3 result = utils::TypedObjectFactory::createNewObject<dynamic::ItemDataV3>();
        result.v(0);
        result.statusCode(e.getCode());
        return result;
    } catch (const privmx::utils::PrivmxException& e) {
        dynamic::ItemDataV3 result = utils::TypedObjectFactory::createNewObject<dynamic::ItemDataV3>();
        result.v(0);
        result.statusCode(core::ExceptionConverter::convert(e).getCode());
        return result;
    } catch (...) {
        dynamic::ItemDataV3 result = utils::TypedObjectFactory::createNewObject<dynamic::ItemDataV3>();
        result.v(0);
        result.statusCode(ENDPOINT_CORE_EXCEPTION_CODE);
        return result;
    }
}

DecryptedItemDataV4 KvdbApiImpl::decryptItemDataV4(server::Item item, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedItemData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedItemDataV4>(item.data());
        return _itemDataEncryptorV4.decrypt(encryptedItemData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedItemDataV4{{.dataStructureVersion = 4, .statusCode = e.getCode()}, {},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedItemDataV4{{.dataStructureVersion = 4, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{}};
    } catch (...) {
        return DecryptedItemDataV4{{.dataStructureVersion = 4, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{}};
    }
}

DecryptedItemDataV5 KvdbApiImpl::decryptItemDataV5(server::Item item, const core::DecryptedEncKey& encKey) {
    try {
        auto encryptedItemData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedItemDataV5>(item.data());
        if(encKey.statusCode != 0) {
            auto tmp = _itemDataEncryptorV5.extractPublic(encryptedItemData);
            tmp.statusCode = encKey.statusCode;
            return tmp;
        }
        return _itemDataEncryptorV5.decrypt(encryptedItemData, encKey.key);
    } catch (const core::Exception& e) {
        return DecryptedItemDataV5{{.dataStructureVersion = 5, .statusCode = e.getCode()}, {},{},{},{},{},{}};
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedItemDataV5{{.dataStructureVersion = 5, .statusCode = core::ExceptionConverter::convert(e).getCode()}, {},{},{},{},{},{}};
    } catch (...) {
        return DecryptedItemDataV5{{.dataStructureVersion = 5, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE}, {},{},{},{},{},{}};
    }
}

Item KvdbApiImpl::convertItemDataV2ToItem(server::Item item, dynamic::ItemDataV2 itemData) {
    Pson::BinaryString data = itemData.textOpt("");
    Poco::JSON::Object::Ptr privateMeta = itemData.copy();
    privateMeta->remove("text");
    privateMeta->remove("statusCode");
    Item ret {
        .info = {
            .kvdbId = item.kvdbId(),
            .itemId = item.id(),
            .createDate = item.createDate(),
            .author = item.author(),
        },
        .publicMeta = core::Buffer(), 
        .privateMeta = core::Buffer::from(privmx::utils::Utils::stringify(privateMeta)),
        .data = core::Buffer::from(data),
        .authorPubKey = itemData.author().pubKey(),
        .statusCode = itemData.statusCodeOpt(0)
    };
    return ret;
}

Item KvdbApiImpl::convertItemDataV3ToItem(server::Item item, dynamic::ItemDataV3 itemData) {
    Item ret {
        .info = {
            .kvdbId = item.kvdbId(),
            .itemId = item.id(),
            .createDate = item.createDate(),
            .author = item.author(),
        },
        .publicMeta = core::Buffer::from(itemData.publicMetaOpt(Pson::BinaryString())), 
        .privateMeta = core::Buffer::from(itemData.privateMetaOpt(Pson::BinaryString())),
        .data = core::Buffer::from(itemData.dataOpt(Pson::BinaryString())),
        .authorPubKey = std::string(),
        .statusCode = itemData.statusCodeOpt(0)
    };
    return ret;
}

Item KvdbApiImpl::convertDecryptedItemDataV4ToItem(server::Item item, DecryptedItemDataV4 itemData) {
    Item ret {
        .info = {
            .kvdbId = item.kvdbId(),
            .itemId = item.id(),
            .createDate = item.createDate(),
            .author = item.author(),
        },
        .publicMeta = itemData.publicMeta, 
        .privateMeta = itemData.privateMeta,
        .data = itemData.data,
        .authorPubKey = itemData.authorPubKey,
        .statusCode = itemData.statusCode
    };
    return ret;
}

Item KvdbApiImpl::convertDecryptedItemDataV5ToItem(server::Item item, DecryptedItemDataV5 itemData) {
    Item ret {
        .info = {
            .kvdbId = item.kvdbId(),
            .itemId = item.id(),
            .createDate = item.createDate(),
            .author = item.author(),
        },
        .publicMeta = itemData.publicMeta, 
        .privateMeta = itemData.privateMeta,
        .data = itemData.data,
        .authorPubKey = itemData.authorPubKey,
        .statusCode = itemData.statusCode
    };
    return ret;
}

Item KvdbApiImpl::decryptAndConvertItemDataToItem(server::Item item, const core::DecryptedEncKey& encKey) {
    // If data is not string, then data is object and has version field
    // Solution with data as object is newer than data as base64 string
    if (item.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::server::VersionedData>(item.data());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
            case 4:
                return convertDecryptedItemDataV4ToItem(item, decryptItemDataV4(item, encKey));
            case 5:
                return convertDecryptedItemDataV5ToItem(item, decryptItemDataV5(item, encKey));
            }
        } 
    } else if (item.data().isString()) {
        // Temporary Solution need better way to dif V3 from V2
        if(core::DataEncryptorUtil::hasSign(utils::Base64::toString(item.data()))) {
            return convertItemDataV3ToItem(item, decryptItemDataV3(item, encKey));
        }
        return convertItemDataV2ToItem(item, decryptItemDataV2(item, encKey));
    }

    auto e = UnknowItemFormatException();
    return Item{{},{},{},{},{},.statusCode = e.getCode()};
}

std::vector<Item> KvdbApiImpl::decryptAndConvertItemsDataToItems(server::KvdbInfo kvdb, utils::List<server::Item> items) {
    std::set<std::string> keyIds;
    for (auto item : items) {
        keyIds.insert(item.keyId());
    }
    auto keyMap = _keyProvider->getKeysAndVerify(kvdb.keys(), keyIds, {.contextId=kvdb.contextId(), .containerId=kvdb.id()});
    std::vector<Item> result;
    for (auto item : items) {

        try {
            auto statusCode = validateItemDataIntegrity(item);
            if(statusCode == 0) {
                result.push_back(decryptAndConvertItemDataToItem(item, keyMap.at(item.keyId())));
            } else {
                result.push_back(Item{{},{},{},{},{},.statusCode = statusCode});
            }
        } catch (const core::Exception& e) {
            result.push_back(Item{{},{},{},{},{},.statusCode = e.getCode()});
        }
    }
    std::vector<core::VerificationRequest> verifierInput {};
    for (auto item: result) {
        if(item.statusCode == 0) {
            verifierInput.push_back({
                .contextId = kvdb.contextId(),
                .senderId = item.info.author,
                .senderPubKey = item.authorPubKey,
                .date = item.info.createDate
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

Item KvdbApiImpl::decryptAndConvertItemDataToItem(server::KvdbInfo kvdb, server::Item item) {
    auto keyId = item.keyId();
    auto encKey = _keyProvider->getKeyAndVerify(kvdb.keys(), keyId, {.contextId=kvdb.contextId(), .containerId=kvdb.id()});
    _itemKeyIdFormatValidator.assertKeyIdFormat(keyId);
    auto result = decryptAndConvertItemDataToItem(item, encKey);
    if(result.statusCode != 0) return result;
    std::vector<core::VerificationRequest> verifierInput {};
        verifierInput.push_back({
            .contextId = kvdb.contextId(),
            .senderId = result.info.author,
            .senderPubKey = result.authorPubKey,
            .date = result.info.createDate
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

Item KvdbApiImpl::decryptAndConvertItemDataToItem(server::Item item) {
    try {
        auto kvdb = getRawKvdbFromCacheOrBridge(item.kvdbId());
        return decryptAndConvertItemDataToItem(kvdb, item);
    } catch (const core::Exception& e) {
        return Item{{},{},{},{},{},.statusCode = e.getCode()};
    } catch (const privmx::utils::PrivmxException& e) {
        return Item{{},{},{},{},{},.statusCode = e.getCode()};
    } catch (...) {
        return Item{{},{},{},{},{},.statusCode = ENDPOINT_CORE_EXCEPTION_CODE};
    }
}

int64_t KvdbApiImpl::decryptKvdbInternalMeta(server::Kvdb2DataEntry kvdbEntry, const core::DecryptedEncKey& encKey) {
    if (kvdbEntry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::server::VersionedData>(kvdbEntry.data());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
            case 4:
                return 0;
            case 5:
                return std::stoll(decryptKvdbV5(kvdbEntry, encKey).internalMeta.stdString());
            }
        } 
    } else if (kvdbEntry.data().isString()) {
        return 0;
    }
    throw UnknowKvdbFormatException();
    return 0;
}

core::DecryptedEncKey KvdbApiImpl::getKvdbCurrentEncKey(server::KvdbInfo kvdb) {
    auto kvdb_data_entry = kvdb.data().get(kvdb.data().size()-1);
    auto key = _keyProvider->getKeyAndVerify(kvdb.keys(), kvdb_data_entry.keyId(), 
        {.contextId=kvdb.contextId(), .containerId=kvdb.id()}
    );
    return key;
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
    if (kvdb_data_entry.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::server::VersionedData>(kvdb_data_entry.data());
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
            case 4:
                return 0;
            case 5: 
                {
                    auto kvdb_data = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKvdbDataV5>(kvdb_data_entry.data());
                    auto dio = _kvdbDataEncryptorV5.getDIOAndAssertIntegrity(kvdb_data);
                    if(
                        dio.containerId != kvdb.id() ||
                        dio.contextId != kvdb.contextId() ||
                        dio.creatorUserId != kvdb.lastModifier()
                        // check timestamp
                    ) {
                        return KvdbDataIntegrityException().getCode();
                    }
                    return 0;
                }
            }
        } 
    } else if(kvdb_data_entry.data().isString()) {
        return 0;
    }
    return UnknowKvdbFormatException().getCode();
}

uint32_t KvdbApiImpl::validateItemDataIntegrity(server::Item item) {
    auto item_data = item.data();
    if (item_data.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<core::server::VersionedData>(item_data);
        if (!versioned.versionEmpty()) {
            switch (versioned.version()) {
            case 4:
                return 0;
            case 5: 
                {
                    auto encData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedItemDataV5>(item_data);
                    auto dio = _itemDataEncryptorV5.getDIOAndAssertIntegrity(encData);
                    if(
                        dio.containerId != item.kvdbId() ||
                        dio.contextId != item.contextId() ||
                        dio.creatorUserId != (item.updates().size() == 0 ? item.author() : item.updates().get(item.updates().size()-1).author())
                        // check timestamp
                    ) {
                        return ItemDataIntegrityException().getCode();
                    }
                    return 0;
                }
            }
        }
    } else if(item_data.isString()) {
        return 0;
    }
    return UnknowItemFormatException().getCode();
}


