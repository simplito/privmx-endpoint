/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/JsonSerializer.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EventVarSerializer.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/utils/Debug.hpp>
#include <privmx/endpoint/core/Factory.hpp>
#include <privmx/endpoint/core/ListQueryMapper.hpp>

#include "privmx/endpoint/stream/StreamApiImpl.hpp"
#include "privmx/endpoint/stream/StreamTypes.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"
#include "privmx/endpoint/stream/DynamicTypes.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

StreamApiImpl::StreamApiImpl(
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
    _serverApi(ServerApi(gateway)) {}

std::string StreamApiImpl::roomCreate(
    const std::string& contextId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>&managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta,
    const std::optional<core::ContainerPolicy>& policies
) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, roomCreate)
    auto streamRoomKey = _keyProvider->generateKey();
    StreamRoomDataToEncrypt streamRoomDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = std::nullopt
    };
    auto create_stream_room_model = utils::TypedObjectFactory::createNewObject<server::StreamRoomCreateModel>();
    create_stream_room_model.contextId(contextId);
    create_stream_room_model.keyId(streamRoomKey.id);
    create_stream_room_model.data(_streamRoomDataEncryptorV4.encrypt(streamRoomDataToEncrypt, _userPrivKey, streamRoomKey.key).asVar());
    auto allUsers = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    privmx::utils::List<core::server::KeyEntrySet> keys = _keyProvider->prepareKeysList(allUsers, streamRoomKey);
    create_stream_room_model.keys(keys);
    create_stream_room_model.users(mapUsers(users));
    create_stream_room_model.managers(mapUsers(managers));
    if (policies.has_value()) {
        create_stream_room_model.policy(core::Factory::createPolicyServerObject(policies.value()));
    }

    auto result = _serverApi.streamRoomCreate(create_stream_room_model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, roomCreate, data send)
    return result.streamRoomId();
}

void StreamApiImpl::roomUpdate(
    const std::string& streamRoomId, 
    const std::vector<core::UserWithPubKey>& users, 
    const std::vector<core::UserWithPubKey>&managers,
    const core::Buffer& publicMeta, 
    const core::Buffer& privateMeta, 
    const int64_t version, 
    const bool force, 
    const bool forceGenerateNewKey, 
    const std::optional<core::ContainerPolicy>& policies
) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, roomUpdate)
    // get current streamRoom
    auto getModel = utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
    getModel.streamRoomId(streamRoomId);
    auto currentStreamRoom = _serverApi.streamRoomGet(getModel).streamRoom();
    // extract current users info
    auto usersVec {core::EndpointUtils::listToVector<std::string>(currentStreamRoom.users())};
    auto managersVec {core::EndpointUtils::listToVector<std::string>(currentStreamRoom.managers())};
    auto oldUsersAll {core::EndpointUtils::uniqueList(usersVec, managersVec)};
    auto new_users = core::EndpointUtils::uniqueListUserWithPubKey(users, managers);
    // adjust key
    std::vector<std::string> usersDiff {core::EndpointUtils::getDifference(oldUsersAll, core::EndpointUtils::usersWithPubKeyToIds(new_users))};
    bool needNewKey = usersDiff.size() > 0;

    auto currentKey {_keyProvider->getKey(currentStreamRoom.keys(), currentStreamRoom.keyId())};
    auto streamRoomKey = forceGenerateNewKey || needNewKey ? _keyProvider->generateKey() : currentKey; 

    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomUpdateModel>();
    model.id(streamRoomId);
    model.keyId(streamRoomKey.id);
    model.keys(_keyProvider->prepareKeysList(new_users, streamRoomKey));
    auto usersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user: users) {
        usersList.add(user.userId);
    }
    auto managersList = utils::TypedObjectFactory::createNewList<std::string>();
    for (auto x: managers) {
        managersList.add(x.userId);
    }
    model.users(usersList);
    model.managers(managersList);
    model.version(version);
    model.force(force);
    if (policies.has_value()) {
        model.policy(privmx::endpoint::core::Factory::createPolicyServerObject(policies.value()));
    }
    StreamRoomDataToEncrypt streamRoomDataToEncrypt {
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .internalMeta = std::nullopt
    };
    model.data(_streamRoomDataEncryptorV4.encrypt(streamRoomDataToEncrypt, _userPrivKey, streamRoomKey.key).asVar());

    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, roomUpdate, data encrypted)
    _serverApi.streamRoomUpdate(model);
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, roomUpdate, data send)
}

core::PagingList<StreamRoom> StreamApiImpl::streamRoomList(const std::string& contextId, const core::PagingQuery& query) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, streamRoomList)
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomListModel>();
    model.contextId(contextId);
    core::ListQueryMapper::map(model, query);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, streamRoomList, getting streamRoomList)
    auto streamRoomsList = _serverApi.streamRoomList(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, streamRoomList, data send)
    std::vector<StreamRoom> streamRooms;
    for (auto streamRoom : streamRoomsList.streamRooms()) {
        streamRooms.push_back(decryptAndConvertStreamRoomDataToStreamRoom(streamRoom));
    }
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, streamRoomList, data decrypted)
    return core::PagingList<StreamRoom>({
        .totalAvailable = streamRoomsList.count(),
        .readItems = streamRooms
    });
}

StreamRoom StreamApiImpl::streamRoomGet(const std::string& streamRoomId) {
    PRIVMX_DEBUG_TIME_START(PlatformStream, streamRoomGet)
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomGetModel>();
    model.streamRoomId(streamRoomId);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, streamRoomGet, getting streamRoom)
    auto streamRoom = _serverApi.streamRoomGet(model);
    PRIVMX_DEBUG_TIME_CHECKPOINT(PlatformStream, streamRoomGet, data send)
    auto result = decryptAndConvertStreamRoomDataToStreamRoom(streamRoom.streamRoom());
    PRIVMX_DEBUG_TIME_STOP(PlatformStream, streamRoomGet, data decrypted)
    return result;
}

void StreamApiImpl::streamRoomDelete(const std::string& streamRoomId) {
    auto model = utils::TypedObjectFactory::createNewObject<server::StreamRoomDeleteModel>();
    model.streamRoomId(streamRoomId);
    _serverApi.streamRoomDelete(model);
}

int64_t StreamApiImpl::streamCreate(const std::string& streamRoomId, const StreamCreateMeta& meta) {
    throw NotImplementedException();
}

void StreamApiImpl::streamUpdate(int64_t streamId, const StreamCreateMeta& meta) {
    throw NotImplementedException();
}

core::PagingList<Stream> StreamApiImpl::streamList(const std::string& streamRoomId, const core::PagingQuery& query) {
    throw NotImplementedException();
}

Stream StreamApiImpl::streamGet(const std::string& streamRoomId, int64_t streamId) {
    throw NotImplementedException();
}

void StreamApiImpl::streamDelete(int64_t streamId) {
    throw NotImplementedException();
}

std::string StreamApiImpl::streamTrackAdd(int64_t streamId, const StreamTrackMeta& meta) {
    throw NotImplementedException();
}

void StreamApiImpl::streamTrackRemove(const std::string& streamTrackId) {
    throw NotImplementedException();
}

List<TrackInfo> StreamApiImpl::streamTrackList(const std::string& streamRoomId, int64_t streamId) {
    throw NotImplementedException();
}

void StreamApiImpl::streamTrackSendData(const std::string& streamTrackId, const core::Buffer& data) {
    throw NotImplementedException();
}

void StreamApiImpl::streamTrackRecvData(const std::string& streamTrackId, std::function<void(const core::Buffer& type)> onData) {
    throw NotImplementedException();
}

void StreamApiImpl::streamPublish(int64_t streamId) {
    throw NotImplementedException();
}

void StreamApiImpl::streamUnpublish(int64_t streamId) {
    throw NotImplementedException();
}

privmx::utils::List<std::string> StreamApiImpl::mapUsers(const std::vector<core::UserWithPubKey>& users) {
    auto result = privmx::utils::TypedObjectFactory::createNewList<std::string>();
    for (auto user : users) {
        result.add(user.userId);
    }
    return result;
}

DecryptedStreamRoomData StreamApiImpl::decryptStreamRoomV4(const server::StreamRoomInfo& streamRoom) {
    try {
        auto streamRoomDataEntry = streamRoom.data().get(streamRoom.data().size()-1);
        auto key = _keyProvider->getKey(streamRoom.keys(), streamRoomDataEntry.keyId());
        auto encryptedStreamRoomData = utils::TypedObjectFactory::createObjectFromVar<server::EncryptedStreamRoomDataV4>(streamRoomDataEntry.data());
        return _streamRoomDataEncryptorV4.decrypt(encryptedStreamRoomData, key.key);
    } catch (const core::Exception& e) {
        return DecryptedStreamRoomData({{},{},{},{},.statusCode = e.getCode()});
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedStreamRoomData({{},{},{},{},.statusCode = core::ExceptionConverter::convert(e).getCode()});
    } catch (...) {
        return DecryptedStreamRoomData({{},{},{},{},.statusCode = ENDPOINT_CORE_EXCEPTION_CODE});
    }
}

StreamRoom StreamApiImpl::convertDecryptedStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoomInfo, const DecryptedStreamRoomData& streamRoomData) {
    std::vector<std::string> users;
    std::vector<std::string> managers;
    for (auto x : streamRoomInfo.users()) {
        users.push_back(x);
    }
    for (auto x : streamRoomInfo.managers()) {
        managers.push_back(x);
    }

    return {
        .contextId = streamRoomInfo.contextId(),
        .streamRoomId = streamRoomInfo.id(),
        .createDate = streamRoomInfo.createDate(),
        .creator = streamRoomInfo.creator(),
        .lastModificationDate = streamRoomInfo.lastModificationDate(),
        .lastModifier = streamRoomInfo.lastModifier(),
        .users = users,
        .managers = managers,
        .version = streamRoomInfo.version(),
        .publicMeta = streamRoomData.publicMeta,
        .privateMeta = streamRoomData.privateMeta,
        .policy = core::Factory::parsePolicyServerObject(streamRoomInfo.policy()), 
        .statusCode = streamRoomData.statusCode
    };
}

StreamRoom StreamApiImpl::decryptAndConvertStreamRoomDataToStreamRoom(const server::StreamRoomInfo& streamRoom) {
    auto storDdataEntry = streamRoom.data().get(streamRoom.data().size()-1);
    auto versioned = utils::TypedObjectFactory::createObjectFromVar<dynamic::VersionedData>(storDdataEntry.data());
    if (!versioned.versionEmpty() && versioned.version() == 4) {
        return convertDecryptedStreamRoomDataToStreamRoom(streamRoom, decryptStreamRoomV4(streamRoom));
    }
    auto e = UnknowStreamRoomFormatException();
    return StreamRoom{{},{},{},{},{},{},{},{},{},{},{},{}, .statusCode = e.getCode()};
}