/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * F-05g: a live publication whose automatic re-key failed is stopped. Each step of the stop runs whatever the
 * others do: the unpublish goes first (an honest Bridge stops forwarding even if the local teardown fails), then the
 * local publisher connection is closed, then the handle and the publisher state are dropped.
 */

#include <gtest/gtest.h>

#include <mutex>
#include <stdexcept>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/stream/StreamApiLowImpl.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>

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
        auto room = std::make_shared<StreamApiLowImpl::StreamRoomData>(nullptr, roomId, webRtc, std::vector<std::string>{});
        room->publisherStream = std::make_shared<StreamApiLowImpl::StreamData>(
            StreamApiLowImpl::StreamData{.sessionId = sessionId, .streamHandle = handle}
        );
        api._streamRoomMap.set(roomId, room);
        api._handleToRoomId.set(handle, roomId);
    }
    static void stopPublication(StreamApiLowImpl& api, const std::string& roomId) {
        api.stopPublication(*api._streamRoomMap.get(roomId).value());
    }
    static bool isPublishing(StreamApiLowImpl& api, const std::string& roomId) {
        return api._streamRoomMap.get(roomId).value()->publisherStream != nullptr;
    }
    static bool hasHandle(StreamApiLowImpl& api, StreamHandle handle) { return api._handleToRoomId.has(handle); }
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
    void updateKeys(const std::string&, const std::vector<stream::Key>&) override {}

private:
    Log& _log;
    bool _failClose;
};

struct ConnectionOf : core::Connection {
    explicit ConnectionOf(const std::shared_ptr<core::ConnectionImpl>& impl) { _ptr = impl; }
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
    // Commit review of 315acd70: a throwing close skipped the handle, the state and the unpublish.
    EXPECT_EQ(stopWith(true, false), UNPUBLISH_THEN_CLOSE);
}

TEST(StreamPublicationStop, AFailedUnpublishStillClosesAndClearsThePublication) {
    EXPECT_EQ(stopWith(false, true), UNPUBLISH_THEN_CLOSE);
}

TEST(StreamPublicationStop, TheUnpublishGoesOutBeforeTheLocalClose) {
    EXPECT_EQ(stopWith(false, false), UNPUBLISH_THEN_CLOSE);
}
