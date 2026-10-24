/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * A live publication whose automatic re-key failed is stopped. Each step of the stop runs whatever the
 * others do: the unpublish goes first (an honest Bridge stops forwarding even if the local teardown fails), then the
 * local publisher connection is closed, then the handle and the publisher state are dropped.
 */

#include <gtest/gtest.h>

#include <mutex>
#include <stdexcept>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>
#include <privmx/endpoint/stream/StreamApiLowImpl.hpp>
#include <privmx/endpoint/stream/encryptors/streamRoom/StreamRoomDataSchemaMapper.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/utils/Utils.hpp>

#include "TestHelpers.hpp"

namespace core = privmx::endpoint::core;
namespace stream = privmx::endpoint::stream;
using privmx::crypto::PrivateKey;

namespace privmx::endpoint::stream {

struct StreamApiLowImplTestAccess {
    // A joined room with a live publication of session `sessionId` under `handle`.
    static void publishing(
        StreamApiLowImpl& api,
        const std::string& roomId,
        const std::shared_ptr<WebRTCInterface>& webRtc,
        int64_t sessionId,
        StreamHandle handle
    ) {
        auto room = std::make_shared<StreamApiLowImpl::StreamRoomData>(
            std::make_shared<DataChannelMessageEncryptorV1>(std::vector<Key>{}), roomId, webRtc, std::vector<std::string>{}
        );
        room->publisherStream = std::make_shared<StreamApiLowImpl::StreamData>(
            StreamApiLowImpl::StreamData{.sessionId = sessionId, .streamHandle = handle}
        );
        api._streamRoomMap.set(roomId, room);
        api._handleToRoomId.set(handle, roomId);
    }
    // The same, joined to `joined`: its resource and context bind the room, its current key is the LOCAL one.
    static void publishing(
        StreamApiLowImpl& api,
        const server::StreamRoomInfo& joined,
        const std::shared_ptr<WebRTCInterface>& webRtc,
        int64_t sessionId,
        StreamHandle handle
    ) {
        publishing(api, joined.id, webRtc, sessionId, handle);
        auto room = api._streamRoomMap.get(joined.id).value();
        room->resourceId = joined.resourceId.value_or("");
        room->contextId = joined.contextId;
        room->localKeyId = joined.keyId;
    }
    static void processNotificationEvent(StreamApiLowImpl& api, const core::NotificationEvent& notification) {
        api.processNotificationEvent(notification);
    }
    static void stopPublication(StreamApiLowImpl& api, const std::string& roomId) {
        api.stopPublication(*api._streamRoomMap.get(roomId).value());
    }
    static bool isPublishing(StreamApiLowImpl& api, const std::string& roomId) {
        return api._streamRoomMap.get(roomId).value()->publisherStream != nullptr;
    }
    static bool hasHandle(StreamApiLowImpl& api, StreamHandle handle) { return api._handleToRoomId.has(handle); }
    static void applyRoomUpdate(StreamApiLowImpl& api, const std::string& roomId, const server::StreamRoomInfo& raw) {
        api.applyRoomUpdate(*api._streamRoomMap.get(roomId).value(), raw);
    }
    // The joined room object itself, as a notification task holds it.
    static std::shared_ptr<void> roomOf(StreamApiLowImpl& api, const std::string& roomId) {
        return api._streamRoomMap.get(roomId).value();
    }
    static void applyRoomUpdateTo(StreamApiLowImpl& api, const std::shared_ptr<void>& room, const server::StreamRoomInfo& raw) {
        api.applyRoomUpdate(*std::static_pointer_cast<StreamApiLowImpl::StreamRoomData>(room), raw);
    }
};

} // namespace privmx::endpoint::stream

namespace {

using Access = stream::StreamApiLowImplTestAccess;

// What happened, in order, across the Bridge and the media layer.
struct Log {
    std::mutex m;
    std::vector<std::string> steps;
    void add(const std::string& step) {
        std::lock_guard<std::mutex> lock(m);
        steps.push_back(step);
    }
};

class Gateway : public privmx::privfs::RpcGateway {
public:
    Gateway(Log& log, bool failUnpublish)
        : RpcGateway(privmx::rpc::AuthorizedConnection::Ptr(), std::nullopt), _log(log), _failUnpublish(failUnpublish) {}
    std::optional<stream::server::StreamRoomInfo> served; // what stream.streamRoomGet answers, when set
    Poco::Dynamic::Var request(
        const std::string& method,
        Poco::JSON::Object::Ptr params,
        privmx::rpc::MessageSendOptionsEx,
        privmx::utils::CancellationToken::Ptr
    ) override {
        _log.add(method + (method == "stream.streamUnpublish" ? " " + params->getValue<std::string>("sessionId") : ""));
        if (_failUnpublish && method == "stream.streamUnpublish") {
            throw std::runtime_error("the bridge is unreachable");
        }
        if (method == "stream.streamRoomGet" && served.has_value()) {
            stream::server::StreamRoomGetResult result;
            result.streamRoom = served.value();
            return overTheWire(result.toJSON());
        }
        if (method == "subscribeToChannels") {
            core::server::SubscribeToChannelsResult result;
            for (const auto& channel : core::server::SubscribeToChannelsModel::fromJSON(overTheWire(params)).channels) {
                result.subscriptions.push_back({.subscriptionId = "sub:" + channel, .channel = channel});
            }
            return overTheWire(result.toJSON());
        }
        return Poco::Dynamic::Var();
    }
    bool isConnected() override { return true; }

private:
    Log& _log;
    bool _failUnpublish;
};

class BrokenWebRTC : public stream::WebRTCInterface {
public:
    BrokenWebRTC(Log& log, bool failClose) : _log(log), _failClose(failClose) {}
    std::string createOfferAndSetLocalDescription(const std::string&, const std::string&) override { return ""; }
    std::string createAnswerAndSetDescriptions(
        const std::string&, const std::string&, const std::string&, const std::string&
    ) override {
        return "";
    }
    void setAnswerAndSetRemoteDescription(
        const std::string&, const std::string&, const std::string&, const std::string&
    ) override {}
    void updateSessionId(const std::string&, const int64_t, const std::string&) override {}
    void closeAll(const std::string&) override {}
    void close(const std::string&, const std::string& connectionType) override {
        _log.add("close " + connectionType);
        if (_failClose) {
            throw std::runtime_error("the peer connection is gone");
        }
    }
    void updateKeys(const std::string&, const std::vector<stream::Key>& keys) override {
        for (const auto& key : keys) {
            if (key.type == stream::KeyType::LOCAL) {
                _log.add("LOCAL " + key.keyId);
            }
        }
    }

private:
    Log& _log;
    bool _failClose;
};

// Stops a live publication (session 42, handle 7) with the Bridge and the media layer failing as asked; returns
// the steps taken. The publisher state must be cleared whatever failed.
std::vector<std::string> stopWith(bool failClose, bool failUnpublish) {
    Log log;
    const PrivateKey key = PrivateKey::generateRandom();
    const privmx::privfs::RpcGateway::Ptr gateway = new Gateway(log, failUnpublish);
    auto impl = std::make_shared<core::ConnectionImpl>();
    impl->connectOver(gateway, key);
    const ConnectionOf connection(impl);
    stream::StreamApiLowImpl api(
        connection, gateway, key, impl->getKeyProvider(), "", impl->getEventMiddleware()
    );
    Access::publishing(api, "room", std::make_shared<BrokenWebRTC>(log, failClose), 42, 7);
    EXPECT_NO_THROW(Access::stopPublication(api, "room"));
    EXPECT_FALSE(Access::isPublishing(api, "room")) << "the publisher state survived";
    EXPECT_FALSE(Access::hasHandle(api, 7)) << "the handle still works";
    std::lock_guard<std::mutex> lock(log.m);
    return log.steps;
}

const std::vector<std::string> UNPUBLISH_THEN_CLOSE{"stream.streamUnpublish 42", "close publisher"};

} // namespace

TEST(StreamPublicationStop, SECURITY_AFailedLocalCloseStillUnpublishesAndClearsThePublication) {
    // A throwing close must not skip the handle, the state or the unpublish.
    EXPECT_EQ(stopWith(true, false), UNPUBLISH_THEN_CLOSE);
}

TEST(StreamPublicationStop, AFailedUnpublishStillClosesAndClearsThePublication) {
    EXPECT_EQ(stopWith(false, true), UNPUBLISH_THEN_CLOSE);
}

TEST(StreamPublicationStop, TheUnpublishGoesOutBeforeTheLocalClose) {
    EXPECT_EQ(stopWith(false, false), UNPUBLISH_THEN_CLOSE);
}

// --- room updates over real keys ----------------------------------------------------------------------------------

// The application's verifier: vouches for everything, or throws when told to.
class Verifier : public core::UserVerifierInterface {
public:
    bool throws = false;
    std::vector<bool> verify(const std::vector<core::VerificationRequest>& requests) override {
        if (throws) {
            throw std::runtime_error("the application's verifier failed");
        }
        return std::vector<bool>(requests.size(), true);
    }
};

// One client joined to "room" (session 42, handle 7), and room states it can open: keys wrapped to it, data it wrote.
struct Joined {
    Log log;
    const PrivateKey key = PrivateKey::generateRandom();
    std::shared_ptr<Verifier> verifier = std::make_shared<Verifier>();
    Gateway* bridge = new Gateway(log, false);
    const privmx::privfs::RpcGateway::Ptr gateway = bridge;
    std::shared_ptr<core::ConnectionImpl> impl = std::make_shared<core::ConnectionImpl>();
    ConnectionOf connection{connect()};
    stream::StreamApiLowImpl api{connection, gateway, key, impl->getKeyProvider(), "", impl->getEventMiddleware()};
    std::shared_ptr<BrokenWebRTC> webRtc = std::make_shared<BrokenWebRTC>(log, false);

    std::shared_ptr<core::ConnectionImpl> connect() {
        impl->setUserVerifier(verifier);
        impl->connectOver(gateway, key);
        return impl;
    }
    core::DataIntegrityObject dio(const std::string& resourceId, const std::string& contextId = "ctx") {
        return {
            .creatorUserId = "me",
            .creatorPubKey = key.getPublicKey().toBase58DER(),
            .contextId = contextId,
            .resourceId = resourceId,
            .timestamp = privmx::utils::Utils::getNowTimestamp(),
            .randomId = privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(8)),
            .containerId = std::nullopt,
            .containerResourceId = std::nullopt,
            .bridgeIdentity = core::BridgeIdentity{.url = "http://localhost/"}
        };
    }
    // "room" holding `keyIds`, `current` as its current key, its data written under `dataKeyId`; another room the
    // user belongs to under another `resourceId`.
    stream::server::StreamRoomInfo state(
        const std::vector<std::string>& keyIds,
        const std::string& current,
        const std::string& dataKeyId,
        const std::string& resourceId = "res",
        const std::string& contextId = "ctx"
    ) {
        stream::server::StreamRoomInfo room;
        room.id = "room";
        room.resourceId = resourceId;
        room.contextId = contextId;
        room.keyId = current;
        for (const auto& keyId : keyIds) {
            for (const auto& entry : impl->getKeyProvider()->prepareKeysList(
                     {{.userId = "me", .pubKey = key.getPublicKey().toBase58DER()}}, keyOf(keyId),
                     dio(resourceId, contextId), {.contextId = contextId, .resourceId = resourceId}, SECRET
                 )) {
                room.keys.push_back({.keyId = entry.keyId, .data = entry.data});
            }
        }
        const auto written = dio(resourceId, contextId);
        stream::StreamRoomDataSchemaMapper mapper(key, connection);
        stream::server::StreamRoomDataEntry entry;
        entry.keyId = dataKeyId;
        entry.data = mapper.encrypt(
            {.publicMeta = core::Buffer::from("pub"),
             .privateMeta = core::Buffer::from("priv"),
             .internalMeta = {.secret = SECRET, .resourceId = resourceId, .randomId = written.randomId},
             .dio = written},
            keyOf(dataKeyId).key
        );
        room.data = {entry};
        room.lastModifier = "me";
        room.lastModificationDate = written.timestamp;
        return room;
    }
    static core::EncKey keyOf(const std::string& keyId) {
        return {.id = keyId, .key = privmx::crypto::Crypto::sha256(keyId)};
    }
    // The app's own subscription to the room's updates; without one no update is handled at all.
    std::string subscribe() {
        return api.subscribeFor({api.buildSubscriptionQuery(
            stream::EventType::STREAMROOM_UPDATE, stream::EventSelectorType::STREAMROOM_ID, "room"
        )})
            .at(0);
    }
    std::vector<std::string> steps() {
        std::lock_guard<std::mutex> lock(log.m);
        return log.steps;
    }
    bool saw(const std::string& step) {
        const auto all = steps();
        return std::find(all.begin(), all.end(), step) != all.end();
    }
    inline static const std::string SECRET = "room-secret";
};

core::NotificationEvent roomUpdated(const stream::server::StreamRoomInfo& raw, const std::string& subscription) {
    return {
        .source = core::EventSource::SERVER,
        .type = "streamRoomUpdated",
        .data = overTheWire(raw.toJSON()),
        .version = 0,
        .timestamp = 0,
        .subscriptions = {subscription}
    };
}

TEST(StreamPublicationStop, SECURITY_AReplayedPreRotationUpdateDoesNotBringTheOldKeyBack) {
    // M2: the room moved k1 -> k2 (a removal); the Bridge then delivers, late or again, the update from before.
    // Applied as it came, the snapshot put the publication back under k1, which the removed member holds, and the
    // fresh read that followed needed no re-key, so nothing moved it on. The keys now come from the fresh read.
    Joined c;
    c.bridge->served = c.state({"k1", "k2"}, "k2", "k2");
    Access::publishing(c.api, c.bridge->served.value(), c.webRtc, 42, 7);
    EXPECT_NO_THROW(Access::applyRoomUpdate(c.api, "room", c.state({"k1"}, "k1", "k1")));
    EXPECT_TRUE(Access::isPublishing(c.api, "room")) << "the live publication was stopped";
    EXPECT_FALSE(c.saw("LOCAL k1")) << "the pre-rotation key was handed to the media layer";
    EXPECT_EQ(c.steps().back(), "LOCAL k2") << "the publication does not end under the room's current key";
}

TEST(StreamPublicationStop, SECURITY_AnUpdateOfAnotherRoomStopsTheLivePublication) {
    // M1: a state of another room the user belongs to, keys and all, under this room's id: its media would go to
    // that room's members. Refused as not the joined room, and the publication stops.
    Joined c;
    c.bridge->served = c.state({"k1"}, "k1", "k1");
    Access::publishing(c.api, c.bridge->served.value(), c.webRtc, 42, 7);
    const auto other = c.state({"k2"}, "k2", "k2", "another-res");
    c.bridge->served = other;
    EXPECT_NO_THROW(Access::applyRoomUpdate(c.api, "room", other));
    EXPECT_FALSE(Access::isPublishing(c.api, "room"));
    EXPECT_FALSE(c.saw("LOCAL k2")) << "another room's key was handed to the media layer";
}

TEST(StreamPublicationStop, SECURITY_AnUpdateTheVerifierCannotJudgeStopsTheLivePublication) {
    // The application's UserVerifier throws while the update is read: it never reached applyRoomUpdate, so the
    // publication went on under whatever key the update replaced.
    Joined c;
    c.bridge->served = c.state({"k1"}, "k1", "k1");
    Access::publishing(c.api, c.bridge->served.value(), c.webRtc, 42, 7);
    const auto subscription = c.subscribe();
    const auto update = c.state({"k1", "k2"}, "k2", "k2");
    c.verifier->throws = true;
    EXPECT_ANY_THROW(Access::processNotificationEvent(c.api, roomUpdated(update, subscription)));
    EXPECT_FALSE(Access::isPublishing(c.api, "room")) << "the publication outlived an update it could not read";
}

TEST(StreamPublicationStop, SECURITY_ARoomUpdateWithNoUsableCurrentKeyStopsTheLivePublication) {
    // The room's current key does not open (here: not among the served keys at all). The live
    // publication is stopped instead of going on under the previous key, and the update does not throw, so the
    // notification handler still emits StreamRoomUpdatedEvent.
    Joined c;
    c.bridge->served = c.state({"k1"}, "k1", "k1");
    Access::publishing(c.api, c.bridge->served.value(), c.webRtc, 42, 7);
    const auto subscription = c.subscribe();
    auto unusable = c.state({"k1"}, "not-served", "k1");
    c.bridge->served = unusable;
    EXPECT_NO_THROW(Access::processNotificationEvent(c.api, roomUpdated(unusable, subscription)));
    EXPECT_FALSE(Access::isPublishing(c.api, "room"));
    const auto steps = c.steps();
    ASSERT_GE(steps.size(), 2u);
    EXPECT_EQ(std::vector<std::string>(steps.end() - 2, steps.end()), UNPUBLISH_THEN_CLOSE);
    EXPECT_NO_THROW(nextEvent("streamRoomUpdated")) << "the app was not told about the update";
}

TEST(StreamPublicationStop, SECURITY_AnUpdateOfTheSameRoomInAnotherContextStopsTheLivePublication) {
    // Only the context differs (same id and resource): still not the joined room.
    Joined c;
    c.bridge->served = c.state({"k1"}, "k1", "k1");
    Access::publishing(c.api, c.bridge->served.value(), c.webRtc, 42, 7);
    const auto other = c.state({"k2"}, "k2", "k2", "res", "another-ctx");
    c.bridge->served = other;
    EXPECT_NO_THROW(Access::applyRoomUpdate(c.api, "room", other));
    EXPECT_FALSE(Access::isPublishing(c.api, "room"));
    EXPECT_FALSE(c.saw("LOCAL k2")) << "another context's key was handed to the media layer";
}

TEST(StreamPublicationStop, SECURITY_AnUpdateNamingTheKeyInUseButStaleIsNotAppliedAsIs) {
    // The update names the LOCAL key, but it needs a re-key (a granted group moved past it). Taken as "the key in use",
    // the publication went on under a key a removed member holds. It is re-keyed or stopped instead.
    Joined c;
    c.bridge->served = c.state({"k1"}, "k1", "k1");
    Access::publishing(c.api, c.bridge->served.value(), c.webRtc, 42, 7);
    auto stale = c.state({"k1"}, "k1", "k1");
    stale.staleGroups = {"g"};
    c.bridge->served = stale; // and no re-key this fake Bridge can take
    EXPECT_NO_THROW(Access::applyRoomUpdate(c.api, "room", stale));
    EXPECT_FALSE(Access::isPublishing(c.api, "room")) << "the publication went on under a stale key";
    EXPECT_FALSE(c.saw("LOCAL k1")) << "the stale key was handed to the media layer again";
}

TEST(StreamPublicationStop, SECURITY_APublicationUpdateFollowsARoomKeyWhoseUpdateWasLost) {
    // The room moved k1 -> k2 and its streamRoomUpdated never arrived: the next update of the publication moves the
    // sender to k2 before it goes out.
    Joined c;
    c.bridge->served = c.state({"k1"}, "k1", "k1");
    Access::publishing(c.api, c.bridge->served.value(), c.webRtc, 42, 7);
    c.bridge->served = c.state({"k1", "k2"}, "k2", "k2");
    try {
        c.api.updateStream(7);
    } catch (...) {} // this fake Bridge answers the update itself with nothing
    const auto steps = c.steps();
    const auto local = std::find(steps.begin(), steps.end(), "LOCAL k2");
    const auto update = std::find(steps.begin(), steps.end(), "stream.streamUpdate");
    ASSERT_NE(local, steps.end()) << "the sender stayed on k1";
    EXPECT_LT(local, update) << "the update went out under k1";
}

TEST(StreamPublicationStop, SECURITY_AnUpdatePendingForALeftRoomTouchesNothingOfTheRoomJoinedAgain) {
    // An update still pending for the room object of a session that was left: the room is joined and published in
    // again under the same id meanwhile. Stopping "its" publication would close the new one's publisher connection.
    Joined c;
    c.bridge->served = c.state({"k1"}, "k1", "k1");
    Access::publishing(c.api, c.bridge->served.value(), c.webRtc, 42, 7);
    const auto old = Access::roomOf(c.api, "room");
    c.api.leaveStreamRoom("room");
    Access::publishing(c.api, c.bridge->served.value(), c.webRtc, 43, 8);
    const auto unusable = c.state({"k1"}, "not-served", "k1");
    c.bridge->served = unusable;
    EXPECT_NO_THROW(Access::applyRoomUpdateTo(c.api, old, unusable));
    EXPECT_FALSE(c.saw("close publisher")) << "the new room's publisher connection was closed";
    EXPECT_FALSE(c.saw("stream.streamUnpublish 42"));
    EXPECT_TRUE(Access::isPublishing(c.api, "room"));
    // Nor are its keys handed to the media layer, which the new room shares.
    const auto moved = c.state({"k1", "k2"}, "k2", "k2");
    c.bridge->served = moved;
    EXPECT_NO_THROW(Access::applyRoomUpdateTo(c.api, old, moved));
    EXPECT_FALSE(c.saw("LOCAL k2")) << "a left room's update moved the new room's sender";
}
