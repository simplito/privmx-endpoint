#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include "../utils/FalseUserVerifierInterface.hpp"
#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/BackendRequester.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/stream/StreamApiImpl.hpp>
#include <privmx/endpoint/stream/StreamVarSerializer.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>

using namespace privmx::endpoint;

class FalseUserVerifierInterface: public virtual core::UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<core::VerificationRequest>& request) override {
        return std::vector<bool>(request.size(), false);
    };
};

class PlainDataCollector : public stream::OnTrackInterface {
public:
    struct Message {
        std::string trackId;
        std::string payload;
        uint64_t seq;
        uint64_t statusCode;
    };

    virtual void OnRemoteTrack(stream::Track tack, stream::TrackAction action) override {
    }
    virtual void OnData(std::shared_ptr<stream::Data> data) override {
        if(data->type != stream::DataType::PLAIN) {
            ADD_FAILURE() << "Unexpected non-plain data received";
            return;
        }
        auto plainData = std::dynamic_pointer_cast<stream::PlainData>(data);
        if(!plainData) {
            ADD_FAILURE() << "Failed to cast incoming data to PlainData";
            return;
        }
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _messages.push_back(Message{
                .trackId = plainData->track,
                .payload = plainData->data.stdString(),
                .seq = plainData->seq,
                .statusCode = plainData->statusCode
            });
        }
        _condition.notify_all();
    }

    bool waitForMessages(size_t expectedCount, const std::chrono::milliseconds& timeout) {
        std::unique_lock<std::mutex> lock(_mutex);
        return _condition.wait_for(lock, timeout, [this, expectedCount]() {
            return _messages.size() >= expectedCount;
        });
    }

    std::vector<Message> messages() const {
        std::lock_guard<std::mutex> lock(_mutex);
        return _messages;
    }

private:
    mutable std::mutex _mutex;
    std::condition_variable _condition;
    std::vector<Message> _messages;
};

class ScopeExit {
public:
    explicit ScopeExit(std::function<void()> callback) : _callback(std::move(callback)) {}

    ~ScopeExit() {
        if(_callback) {
            _callback();
        }
    }

private:
    std::function<void()> _callback;
};

enum ConnectionType {
    User1,
    User2,
    Public
};

class StreamTest : public privmx::test::BaseTest {
protected:
    struct StreamClient {
        std::string userId;
        std::string pubKey;
        std::string privKey;
        std::shared_ptr<core::Connection> connection;
        std::shared_ptr<event::EventApi> eventApi;
        std::shared_ptr<stream::StreamApi> streamApi;

        void disconnect() {
            if(connection) {
                connection->disconnect();
            }
            streamApi.reset();
            eventApi.reset();
            connection.reset();
        }
    };

    StreamTest() : BaseTest(privmx::test::BaseTestMode::online) {}
    void connectAs(ConnectionType type) {
        if(type == ConnectionType::User1) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_1_privKey"),
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        } else if(type == ConnectionType::User2) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connect(
                    reader->getString("Login.user_2_privKey"),
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        } else if(type == ConnectionType::Public) {
            connection = std::make_shared<core::Connection>(
                core::Connection::connectPublic(
                    reader->getString("Login.solutionId"),
                    getPlatformUrl(reader->getString("Login.instanceUrl"))
                )
            );
        }
        eventApi = std::make_shared<event::EventApi>(event::EventApi::create(*connection));
        streamApi = std::make_shared<stream::StreamApi>(
            stream::StreamApi::create(
                *connection,
                *eventApi
            )
        );
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        eventApi.reset();
        streamApi.reset();
    }
    void customSetUp() override {
        reader = new Poco::Util::IniFileConfiguration(INI_FILE_PATH);
        connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_1_privKey"),
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
        eventApi = std::make_shared<event::EventApi>(event::EventApi::create(*connection));
        streamApi = std::make_shared<stream::StreamApi>(
            stream::StreamApi::create(
                *connection,
                *eventApi
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        eventApi.reset();
        streamApi.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    std::string fastStreamRoom(const std::string& contextId) {
        return streamApi->createStreamRoom(
            contextId,
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{.userId=reader->getString("Login.user_1_id"),.pubKey=reader->getString("Login.user_1_pubKey")},
                core::UserWithPubKey{.userId=reader->getString("Login.user_2_id"), .pubKey=reader->getString("Login.user_2_pubKey")}
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{.userId=reader->getString("Login.user_1_id"),.pubKey=reader->getString("Login.user_1_pubKey")},
                core::UserWithPubKey{.userId=reader->getString("Login.user_2_id"), .pubKey=reader->getString("Login.user_2_pubKey")}
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt
        );
    }
    stream::StreamHandle publishStream(const std::string& streamRoomId) {
        streamApi->joinStreamRoom(streamRoomId);
        stream::StreamHandle handle = streamApi->createStream(streamRoomId);
        std::vector<stream::VideoDevice> mediaDevices = streamApi->getVideoDevices();
        streamApi->getImpl()->addFakeVideoTrack(handle);
        streamApi->publishStream(handle);
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        return handle;
    }
    stream::StreamHandle publishDataStream(const std::shared_ptr<stream::StreamApi>& api, const std::string& streamRoomId) {
        api->joinStreamRoom(streamRoomId);
        stream::StreamHandle handle = api->createStream(streamRoomId);
        api->getImpl()->addTrack(handle, {"", "", stream::DeviceType::Plain}, stream::MediaTrackConstrains{});
        api->publishStream(handle);
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        return handle;
    }
    StreamClient createClient(const std::string& userId, const std::string& pubKey, const std::string& privKey) {
        StreamClient client;
        client.userId = userId;
        client.pubKey = pubKey;
        client.privKey = privKey;
        client.connection = std::make_shared<core::Connection>(
            core::Connection::connect(
                privKey,
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );

        client.eventApi = std::make_shared<event::EventApi>(
            event::EventApi::create(*client.connection)
        );

        client.streamApi = std::make_shared<stream::StreamApi>(
            stream::StreamApi::create(*client.connection, *client.eventApi)
        );

        return client;
    }
    Poco::JSON::Object::Ptr backendRequest(const std::string& method, Poco::JSON::Object::Ptr params) {
        auto response = core::BackendRequester::backendRequest(
            getPlatformUrl(reader->getString("Login.instanceUrl")),
            "api_key_id",
            "api_key_secret",
            0,
            method,
            privmx::utils::Utils::stringify(params)
        );
        return privmx::utils::Utils::parseJsonObject(response);
    }
    std::string stringifyJson(Poco::JSON::Object::Ptr object) {
        std::stringstream stream;
        object->stringify(stream);
        return stream.str();
    }

    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<event::EventApi> eventApi;
    std::shared_ptr<stream::StreamApi> streamApi;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(StreamTest, createStreamRoom) {
    // different users and managers
    std::string streamRoomId;
    stream::StreamRoom streamRoom;
    EXPECT_NO_THROW({
        streamRoomId = streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_2_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt
        );
    });
    if(streamRoomId.empty()) {
        FAIL();
    }
    EXPECT_NO_THROW({
        streamRoom = streamApi->getStreamRoom(
            streamRoomId
        );
    });
    EXPECT_EQ(streamRoom.statusCode, 0);
    EXPECT_EQ(streamRoom.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(streamRoom.publicMeta.stdString(), "public");
    EXPECT_EQ(streamRoom.privateMeta.stdString(), "private");
    EXPECT_EQ(streamRoom.users.size(), 1);
    if(streamRoom.users.size() == 1) {
        EXPECT_EQ(streamRoom.users[0], reader->getString("Login.user_2_id"));
    }
    EXPECT_EQ(streamRoom.managers.size(), 1);
    if(streamRoom.managers.size() == 1) {
        EXPECT_EQ(streamRoom.managers[0], reader->getString("Login.user_1_id"));
    }
    // same users and managers
    EXPECT_NO_THROW({
        streamRoomId = streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt
        );
    });
    if(streamRoomId.empty()) {
        FAIL();
    }
    EXPECT_NO_THROW({
        streamRoom = streamApi->getStreamRoom(
            streamRoomId
        );
    });
    EXPECT_EQ(streamRoom.statusCode, 0);
    EXPECT_EQ(streamRoom.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(streamRoom.publicMeta.stdString(), "public");
    EXPECT_EQ(streamRoom.privateMeta.stdString(), "private");
    EXPECT_EQ(streamRoom.users.size(), 1);
    if(streamRoom.users.size() == 1) {
        EXPECT_EQ(streamRoom.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(streamRoom.managers.size(), 1);
    if(streamRoom.managers.size() == 1) {
        EXPECT_EQ(streamRoom.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(StreamTest, listStreamRooms_incorrect_input_data) {
    // incorrect contextId
    EXPECT_THROW({
        streamApi->listStreamRooms(
            "invalid_context_id",
            {
                .skip=0,
                .limit=1,
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit < 0
    EXPECT_THROW({
        streamApi->listStreamRooms(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=-1,
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // limit == 0
    EXPECT_THROW({
        streamApi->listStreamRooms(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=0,
                .sortOrder="desc"
            }
        );
    }, core::Exception);
    // incorrect sortOrder
    EXPECT_THROW({
        streamApi->listStreamRooms(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="BLACH"
            }
        );
    }, core::Exception);
    // incorrect lastId
    EXPECT_THROW({
        streamApi->listStreamRooms(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="desc",
                .lastId=reader->getString("Context_1.contextId")
            }
        );
    }, core::Exception);
    // incorrect queryAsJson
    EXPECT_THROW({
        streamApi->listStreamRooms(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="desc",
                .lastId=std::nullopt,
                .queryAsJson="{BLACH,}"
            }
        );
    }, core::InvalidParamsException);
    // incorrect sortBy
    EXPECT_THROW({
        streamApi->listStreamRooms(
            reader->getString("Context_1.contextId"),
            core::PagingQuery{
                .skip=0,
                .limit=1,
                .sortOrder="desc",
                .lastId=std::nullopt,
                .sortBy="blach",
                .queryAsJson=std::nullopt
            }
        );
    }, core::InvalidParamsException);
}

TEST_F(StreamTest, listStreamRooms_correct_input_data) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    auto streamRoomId_2 = fastStreamRoom(reader->getString("Context_1.contextId"));
    auto streamRoomId_3 = fastStreamRoom(reader->getString("Context_1.contextId"));

    core::PagingList<stream::StreamRoom> listStreamRooms;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listStreamRooms = streamApi->listStreamRooms(
            reader->getString("Context_1.contextId"),
            {
                .skip=4,
                .limit=1,
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listStreamRooms.totalAvailable, 3);
    EXPECT_EQ(listStreamRooms.readItems.size(), 0);
    // {.skip=0, .limit=1, .sortOrder="asc"}
    EXPECT_NO_THROW({
        listStreamRooms = streamApi->listStreamRooms(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="desc"
            }
        );
    });
    EXPECT_EQ(listStreamRooms.totalAvailable, 3);
    EXPECT_EQ(listStreamRooms.readItems.size(), 1);
    if(listStreamRooms.readItems.size() >= 1) {
        auto stream = listStreamRooms.readItems[0];
        EXPECT_EQ(stream.streamRoomId, streamRoomId_3);
        EXPECT_EQ(stream.statusCode, 0);
    }
    // {.skip=1, .limit=3, .sortOrder="asc"}
    EXPECT_NO_THROW({
        listStreamRooms = streamApi->listStreamRooms(
            reader->getString("Context_1.contextId"),
            {
                .skip=1,
                .limit=3,
                .sortOrder="asc"
            }
        );
    });
    EXPECT_EQ(listStreamRooms.totalAvailable, 3);
    EXPECT_EQ(listStreamRooms.readItems.size(), 2);
    if(listStreamRooms.readItems.size() >= 1) {
        auto stream = listStreamRooms.readItems[0];
        EXPECT_EQ(stream.streamRoomId, streamRoomId_2);
        EXPECT_EQ(stream.statusCode, 0);
    }
    if(listStreamRooms.readItems.size() >= 2) {
        auto stream = listStreamRooms.readItems[1];
        EXPECT_EQ(stream.streamRoomId, streamRoomId_3);
        EXPECT_EQ(stream.statusCode, 0);
    }

}

TEST_F(StreamTest, updateStreamRoom_incorrect_data) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    // incorrect streamRoomId
    EXPECT_THROW({
        streamApi->updateStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false,
            std::nullopt
        );
    }, core::Exception);
    // incorrect users
    EXPECT_THROW({
        streamApi->updateStreamRoom(
            streamRoomId_1,
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false,
            std::nullopt
        );
    }, core::Exception);
    // incorrect managers
    EXPECT_THROW({
        streamApi->updateStreamRoom(
            streamRoomId_1,
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_2_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false,
            std::nullopt
        );
    }, core::Exception);
    // no managers
    EXPECT_THROW({
        streamApi->updateStreamRoom(
            streamRoomId_1,
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false,
            std::nullopt
        );
    }, core::Exception);
    // incorrect version force false
    EXPECT_THROW({
        streamApi->updateStreamRoom(
            streamRoomId_1,
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            99,
            false,
            false,
            std::nullopt
        );
    }, core::Exception);
}

TEST_F(StreamTest, updateStreamRoom_correct_data) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    auto streamRoomId_2 = fastStreamRoom(reader->getString("Context_1.contextId"));
    stream::StreamRoom streamRoom;
    // less users
    EXPECT_NO_THROW({
        streamApi->updateStreamRoom(
            streamRoomId_1,
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                },
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_2_id"),
                    .pubKey=reader->getString("Login.user_2_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false,
            std::nullopt
        );
    });
    EXPECT_NO_THROW({
        streamRoom = streamApi->getStreamRoom(
            streamRoomId_1
        );
    });
    EXPECT_EQ(streamRoom.statusCode, 0);
    EXPECT_EQ(streamRoom.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(streamRoom.version, 2);
    EXPECT_EQ(streamRoom.publicMeta.stdString(), "public");
    EXPECT_EQ(streamRoom.privateMeta.stdString(), "private");
    EXPECT_EQ(streamRoom.users.size(), 1);
    if(streamRoom.users.size() == 1) {
        EXPECT_EQ(streamRoom.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(streamRoom.managers.size(), 2);
    if(streamRoom.managers.size() == 2) {
        EXPECT_EQ(streamRoom.managers[0], reader->getString("Login.user_1_id"));
        EXPECT_EQ(streamRoom.managers[1], reader->getString("Login.user_2_id"));
    }
    // less managers
    EXPECT_NO_THROW({
        streamApi->updateStreamRoom(
            streamRoomId_1,
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            2,
            false,
            false,
            std::nullopt
        );
    });
    EXPECT_NO_THROW({
        streamRoom = streamApi->getStreamRoom(
            streamRoomId_1
        );
    });
    EXPECT_EQ(streamRoom.statusCode, 0);
    EXPECT_EQ(streamRoom.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(streamRoom.version, 3);
    EXPECT_EQ(streamRoom.publicMeta.stdString(), "public");
    EXPECT_EQ(streamRoom.privateMeta.stdString(), "private");
    EXPECT_EQ(streamRoom.users.size(), 1);
    if(streamRoom.users.size() == 1) {
        EXPECT_EQ(streamRoom.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(streamRoom.managers.size(), 1);
    if(streamRoom.managers.size() == 1) {
        EXPECT_EQ(streamRoom.managers[0], reader->getString("Login.user_1_id"));
    }
    // incorrect version force true
    EXPECT_NO_THROW({
        streamApi->updateStreamRoom(
            streamRoomId_2,
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            99,
            true,
            false,
            std::nullopt
        );
    });
    EXPECT_NO_THROW({
        streamRoom = streamApi->getStreamRoom(
            streamRoomId_2
        );
    });
    EXPECT_EQ(streamRoom.statusCode, 0);
    EXPECT_EQ(streamRoom.contextId, reader->getString("Context_1.contextId"));
    EXPECT_EQ(streamRoom.version, 2);
    EXPECT_EQ(streamRoom.publicMeta.stdString(), "public");
    EXPECT_EQ(streamRoom.privateMeta.stdString(), "private");
    EXPECT_EQ(streamRoom.users.size(), 1);
    if(streamRoom.users.size() == 1) {
        EXPECT_EQ(streamRoom.users[0], reader->getString("Login.user_1_id"));
    }
    EXPECT_EQ(streamRoom.managers.size(), 1);
    if(streamRoom.managers.size() == 1) {
        EXPECT_EQ(streamRoom.managers[0], reader->getString("Login.user_1_id"));
    }
}

TEST_F(StreamTest, deleteStream) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    // incorrect streamRoomId
    EXPECT_THROW({
        streamApi->deleteStreamRoom(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // as manager
     EXPECT_NO_THROW({
        streamApi->deleteStreamRoom(
            streamRoomId_1
        );
    });
    EXPECT_THROW({
        streamApi->getStreamRoom(
            streamRoomId_1
        );
    }, core::Exception);
}

TEST_F(StreamTest, userValidator_false) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    auto streamRoomId_2 = fastStreamRoom(reader->getString("Context_1.contextId"));
    auto verifier = std::make_shared<core::FalseUserVerifierInterface>();
    connection->setUserVerifier(verifier);
    // getStreamRoom
    EXPECT_NO_THROW({
        auto Stream = streamApi->getStreamRoom(
            streamRoomId_1
        );
        EXPECT_FALSE(Stream.statusCode == 0);
    });
    // listStreamRooms
    EXPECT_NO_THROW({
        auto Streams = streamApi->listStreamRooms(
            reader->getString("Context_1.contextId"),
            {
                .skip=0,
                .limit=1,
                .sortOrder="desc"
            }
        );
        EXPECT_FALSE(Streams.readItems[0].statusCode == 0);
    });
    // createStream
    EXPECT_NO_THROW({
        streamApi->createStreamRoom(
            reader->getString("Context_1.contextId"),
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt
        );
    });
    EXPECT_THROW({
        streamApi->updateStreamRoom(
            streamRoomId_1,
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                .userId=reader->getString("Login.user_1_id"),
                .pubKey=reader->getString("Login.user_1_pubKey")
            }},
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            true,
            true,
            std::nullopt
        );
    }, core::Exception);
    // deleteStream
    EXPECT_NO_THROW({
        streamApi->deleteStreamRoom(
            streamRoomId_2
        );
    });
}

TEST_F(StreamTest, falseUserVerifierInterface) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->updateStreamRoom(
            streamRoomId_1,
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            std::vector<core::UserWithPubKey>{
                core::UserWithPubKey{
                    .userId=reader->getString("Login.user_1_id"),
                    .pubKey=reader->getString("Login.user_1_pubKey")
                }
            },
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            1,
            false,
            false,
            std::nullopt
        );
    });

    EXPECT_NO_THROW({
        std::shared_ptr<FalseUserVerifierInterface> falseUserVerifierInterface = std::make_shared<FalseUserVerifierInterface>();
        connection->setUserVerifier(falseUserVerifierInterface);
    });

    core::PagingList<stream::StreamRoom> streamListResult;
    EXPECT_NO_THROW({
        streamListResult = streamApi->listStreamRooms(reader->getString("Context_1.contextId"),{.skip=0, .limit=1, .sortOrder="desc"});
    });
    if(streamListResult.readItems.size() == 1) {
        EXPECT_EQ(streamListResult.readItems[0].statusCode, core::UserVerificationFailureException().getCode());
    } else {
        FAIL();
    }
}

TEST_F(StreamTest, listStreams_empty_room) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_THROW({
        streamApi->listStreams(reader->getString("Context_1.contextId"));
    }, core::Exception);

    EXPECT_NO_THROW({
        streamApi->listStreams(streamRoomId_1);
    });
}

TEST_F(StreamTest, joinStreamRoom) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_THROW({
        streamApi->joinStreamRoom(reader->getString("Context_1.contextId"));
    }, core::Exception);

    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    EXPECT_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    }, core::Exception);
}

TEST_F(StreamTest, leaveStreamRoom) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    EXPECT_THROW({
        streamApi->leaveStreamRoom(reader->getString("Context_1.contextId"));
    }, core::Exception);
    EXPECT_NO_THROW({
        streamApi->leaveStreamRoom(streamRoomId_1);
    });
    EXPECT_THROW({
        streamApi->leaveStreamRoom(streamRoomId_1);
    }, core::Exception);
}

TEST_F(StreamTest, createStream) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_THROW({
        auto handle = streamApi->createStream(reader->getString("Context_1.contextId"));
    }, core::Exception);

    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    EXPECT_THROW({
        auto handle = streamApi->createStream(reader->getString("Context_1.contextId"));
    }, core::Exception);
    EXPECT_NO_THROW({
        auto handle = streamApi->createStream(streamRoomId_1);
    });
}

TEST_F(StreamTest, adding_Track_no_publish) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    stream::StreamHandle handle;
    EXPECT_NO_THROW({
        handle = streamApi->createStream(streamRoomId_1);
    });
    // Load Fake video track
    EXPECT_NO_THROW({
        streamApi->getImpl()->addFakeVideoTrack(handle);
    });
}

TEST_F(StreamTest, publish_no_tracks) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    stream::StreamHandle handle;
    EXPECT_NO_THROW({
        handle = streamApi->createStream(streamRoomId_1);
    });
    EXPECT_THROW({
        streamApi->publishStream(handle);
    }, core::Exception);
}

TEST_F(StreamTest, publish_with_tracks) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    stream::StreamHandle handle;
    EXPECT_NO_THROW({
        handle = streamApi->createStream(streamRoomId_1);
    });
    // Load Fake video track
    EXPECT_NO_THROW({
        streamApi->getImpl()->addFakeVideoTrack(handle);
    });
    EXPECT_THROW({
        streamApi->publishStream(-1);
    }, core::Exception);
    EXPECT_NO_THROW({
        streamApi->publishStream(handle);
    });
    EXPECT_THROW({
        streamApi->publishStream(handle);
    }, core::Exception);
}

TEST_F(StreamTest, publish_with_multiple_instance_of_same_track) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    stream::StreamHandle handle;
    EXPECT_NO_THROW({
        handle = streamApi->createStream(streamRoomId_1);
    });
    // Load Fake video tracks
    EXPECT_NO_THROW({
        streamApi->getImpl()->addFakeVideoTrack(handle);
        streamApi->getImpl()->addFakeVideoTrack(handle);
    });
    EXPECT_NO_THROW({
        streamApi->publishStream(handle);
    });
}

TEST_F(StreamTest, subscribeToRemoteStreams_no_streams) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    EXPECT_THROW({
        streamApi->subscribeToRemoteStreams(streamRoomId_1, {});
    }, core::Exception); 
}

TEST_F(StreamTest, unsubscribeFromRemoteStreams_no_streams) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    EXPECT_THROW({
        streamApi->unsubscribeFromRemoteStreams(streamRoomId_1, {});
    }, core::Exception);
}

TEST_F(StreamTest, subscribeToRemoteStreams) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        publishStream(streamRoomId_1);
    });
    // // invalid StreamSubscription
    std::vector<stream::StreamSubscription> invalid_streamsId = {{99999, "invalid"}};
    EXPECT_THROW({
        streamApi->subscribeToRemoteStreams(streamRoomId_1, invalid_streamsId);
    }, core::Exception);
    // valid StreamSubscription
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    std::vector<stream::StreamSubscription> streamsId;
    EXPECT_NO_THROW({
        auto streamlist = streamApi->listStreams(streamRoomId_1);
        std::cout << "streamlist.size():" << streamlist.size()  << std::endl;
        for(auto stream : streamlist) {
            std::cout << "stream.tracks.size():" << stream.tracks.size()  << std::endl;
            for(auto track : stream.tracks) {
                streamsId.push_back(stream::StreamSubscription{stream.id, track.mid});

                std::cout << "stream.id:" << stream.id << " | track.mid:" << track.mid << std::endl;
            }
        }
    });
    if(streamsId.size() != 0) {
        EXPECT_NO_THROW({
            streamApi->subscribeToRemoteStreams(streamRoomId_1, streamsId);
        });
    } else {
        std::cerr << "No streams on bridge" << std::endl; 
        FAIL();
    }
}

TEST_F(StreamTest, unsubscribeFromRemoteStreams) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        publishStream(streamRoomId_1);
    });
    std::vector<stream::StreamSubscription> streamsId;
    EXPECT_NO_THROW({
        auto streamlist = streamApi->listStreams(streamRoomId_1);
        for(auto stream : streamlist) {
            for(auto track : stream.tracks) {
                streamsId.push_back(stream::StreamSubscription{stream.id, track.mid});
            }
        }
    });
    EXPECT_NO_THROW({
        streamApi->subscribeToRemoteStreams(streamRoomId_1, streamsId);
    });
    // invalid StreamSubscription
    std::vector<stream::StreamSubscription> invalid_streamsId = {{-1, "invalid"}};
    EXPECT_THROW({
        streamApi->unsubscribeFromRemoteStreams(streamRoomId_1, invalid_streamsId);
    }, core::Exception);
    EXPECT_NO_THROW({
        streamApi->unsubscribeFromRemoteStreams(streamRoomId_1, streamsId);
    });
}

TEST_F(StreamTest, updateStream_remove_all_tracks) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    stream::StreamHandle handle;
    EXPECT_NO_THROW({
        handle = streamApi->createStream(streamRoomId_1);
    });
    // Load Fake video track
    EXPECT_NO_THROW({
        streamApi->getImpl()->addFakeVideoTrack(handle);
    });
    EXPECT_NO_THROW({
        streamApi->publishStream(handle);
    });
    EXPECT_NO_THROW({
        streamApi->removeTrack(handle, {"FAKE", "FAKE",stream::DeviceType::Video});
    });
    EXPECT_NO_THROW({
    streamApi->updateStream(handle);
    });
}

TEST_F(StreamTest, updateStream_adding_track) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    stream::StreamHandle handle;
    EXPECT_NO_THROW({
        handle = streamApi->createStream(streamRoomId_1);
    });
    // Load Fake video track
    EXPECT_NO_THROW({
        streamApi->getImpl()->addFakeVideoTrack(handle);
    });
    EXPECT_NO_THROW({
        streamApi->publishStream(handle);
    });
    // Load Fake video track
    EXPECT_NO_THROW({
        streamApi->getImpl()->addFakeVideoTrack(handle);
    });
    EXPECT_NO_THROW({
        streamApi->updateStream(handle);
    });
}

TEST_F(StreamTest, updateStream_no_changes) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    stream::StreamHandle handle;
    EXPECT_NO_THROW({
        handle = streamApi->createStream(streamRoomId_1);
    });
    // Load Fake video track
    EXPECT_NO_THROW({
        streamApi->getImpl()->addFakeVideoTrack(handle);
    });
    EXPECT_NO_THROW({
        streamApi->publishStream(handle);
    });
    EXPECT_NO_THROW({
        streamApi->updateStream(handle);
    });
}

TEST_F(StreamTest, updateStream_after_failed_add_track) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    stream::StreamHandle handle;
    EXPECT_NO_THROW({
        handle = streamApi->createStream(streamRoomId_1);
    });
    // Load Fake video track
    EXPECT_NO_THROW({
        streamApi->getImpl()->addFakeVideoTrack(handle);
    });
    EXPECT_NO_THROW({
        streamApi->publishStream(handle);
    });
    EXPECT_THROW({
        streamApi->addTrack(handle, {"invalid", "invalid", stream::DeviceType::Audio}, {});
    }, core::Exception);
    EXPECT_NO_THROW({
        streamApi->updateStream(handle);
    });
}

TEST_F(StreamTest, updateStream_after_unpublishing) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
    });
    stream::StreamHandle handle;
    EXPECT_NO_THROW({
        handle = streamApi->createStream(streamRoomId_1);
    });
    // Load Fake video track
    EXPECT_NO_THROW({
        streamApi->getImpl()->addFakeVideoTrack(handle);
    });
    EXPECT_NO_THROW({
        streamApi->publishStream(handle);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_NO_THROW({
        streamApi->unpublishStream(handle);
    });
    EXPECT_THROW({
        streamApi->updateStream(handle);
    }, core::Exception);
}

TEST_F(StreamTest, modifyRemoteStreamsSubscriptions_invalid_data) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        publishStream(streamRoomId_1);
    });
    std::vector<stream::StreamSubscription> streamsId;
    EXPECT_NO_THROW({
        auto streamlist = streamApi->listStreams(streamRoomId_1);
        for(auto stream : streamlist) {
            for(auto track : stream.tracks) {
                streamsId.push_back(stream::StreamSubscription{stream.id, track.mid});
            }
        }
    });
    EXPECT_NO_THROW({
        streamApi->subscribeToRemoteStreams(streamRoomId_1, streamsId);
    });
    //no change
    EXPECT_THROW({
        streamApi->modifyRemoteStreamsSubscriptions(streamRoomId_1, {}, {});
    }, core::Exception);
    //add invalid
    EXPECT_THROW({
        streamApi->modifyRemoteStreamsSubscriptions(streamRoomId_1, {{-1, "invalid"}}, {});
    }, core::Exception);
    //remove invalid
    EXPECT_THROW({
        streamApi->modifyRemoteStreamsSubscriptions(streamRoomId_1, {}, {{-1, "invalid"}});
    }, core::Exception);
    //add invalid, remove valid
    EXPECT_THROW({
        streamApi->modifyRemoteStreamsSubscriptions(streamRoomId_1, {{-1, "invalid"}}, streamsId);
    }, core::Exception);
    //add valid, remove invalid
    EXPECT_THROW({
        streamApi->modifyRemoteStreamsSubscriptions(streamRoomId_1, streamsId, {{-1, "invalid"}});
    }, core::Exception);
}

TEST_F(StreamTest, modifyRemoteStreamsSubscriptions_remove_all_tracks) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        publishStream(streamRoomId_1);
    });
    std::vector<stream::StreamSubscription> streamsId;
    EXPECT_NO_THROW({
        auto streamlist = streamApi->listStreams(streamRoomId_1);
        for(auto stream : streamlist) {
            for(auto track : stream.tracks) {
                streamsId.push_back(stream::StreamSubscription{stream.id, track.mid});
            }
        }
    });
    EXPECT_NO_THROW({
        streamApi->subscribeToRemoteStreams(streamRoomId_1, streamsId);
    });

    EXPECT_NO_THROW({
        streamApi->modifyRemoteStreamsSubscriptions(streamRoomId_1, {}, streamsId);
    });
}

TEST_F(StreamTest, modifyRemoteStreamsSubscriptions_add_new_track) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        publishStream(streamRoomId_1);
    });
    std::vector<stream::StreamSubscription> streamsId;
    EXPECT_NO_THROW({
        auto streamlist = streamApi->listStreams(streamRoomId_1);
        for(auto stream : streamlist) {
            for(auto track : stream.tracks) {
                streamsId.push_back(stream::StreamSubscription{stream.id, track.mid});
            }
        }
    });
    EXPECT_NO_THROW({
        streamApi->subscribeToRemoteStreams(streamRoomId_1, streamsId);
    });
    EXPECT_NO_THROW({
        streamApi->modifyRemoteStreamsSubscriptions(streamRoomId_1, streamsId, {});
    });
}

TEST_F(StreamTest, modifyRemoteStreamsSubscriptions_add_and_remove_same_track) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        publishStream(streamRoomId_1);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    std::vector<stream::StreamSubscription> streamsId;
    EXPECT_NO_THROW({
        auto streamlist = streamApi->listStreams(streamRoomId_1);
        for(auto stream : streamlist) {
            for(auto track : stream.tracks) {
                streamsId.push_back(stream::StreamSubscription{stream.id, track.mid});
            }
        }
    });
    EXPECT_NO_THROW({
        streamApi->subscribeToRemoteStreams(streamRoomId_1, streamsId);
    });
    EXPECT_NO_THROW({
        streamApi->modifyRemoteStreamsSubscriptions(streamRoomId_1, streamsId, streamsId);
    });
}

TEST_F(StreamTest, modifyRemoteStreamsSubscriptions_after_unpublish) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    stream::StreamHandle handle;
    EXPECT_NO_THROW({
        handle = publishStream(streamRoomId_1);
    });
    std::vector<stream::StreamSubscription> streamsId;
    EXPECT_NO_THROW({
        auto streamlist = streamApi->listStreams(streamRoomId_1);
        for(auto stream : streamlist) {
            for(auto track : stream.tracks) {
                streamsId.push_back(stream::StreamSubscription{stream.id, track.mid});
                streamsId.push_back(stream::StreamSubscription{stream.id, track.mid});
            }
        }
    });
    EXPECT_NO_THROW({
        streamApi->subscribeToRemoteStreams(streamRoomId_1, streamsId);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_NO_THROW({
        streamApi->unpublishStream(handle);
    });
    EXPECT_THROW({
        streamApi->modifyRemoteStreamsSubscriptions(streamRoomId_1, {}, streamsId);
    }, core::Exception);
}

TEST_F(StreamTest, user_3_can_connect) {
    std::shared_ptr<core::Connection> connection3;
    ScopeExit cleanup([&connection3]() {
        if(connection3) {
            try {
                connection3->disconnect();
            } catch(...) {
            }
            connection3.reset();
        }
    });

    EXPECT_NO_THROW({
        connection3 = std::make_shared<core::Connection>(
            core::Connection::connect(
                reader->getString("Login.user_3_privKey"),
                reader->getString("Login.solutionId"),
                getPlatformUrl(reader->getString("Login.instanceUrl"))
            )
        );
    });
    ASSERT_NE(connection3, nullptr);
}

TEST_F(StreamTest, dataChannel_send_and_get) {
    auto client2 = createClient(
        reader->getString("Login.user_2_id"),
        reader->getString("Login.user_2_pubKey"),
        reader->getString("Login.user_2_privKey")
    );
    ScopeExit cleanup([&client2]() { client2.disconnect(); });
    //Publish Data Track as user_1
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    stream::StreamHandle handle_USER_1;
    EXPECT_NO_THROW({
        streamApi->joinStreamRoom(streamRoomId_1);
        handle_USER_1 = streamApi->createStream(streamRoomId_1);
        streamApi->getImpl()->addTrack(handle_USER_1, {"","",stream::DeviceType::Plain}, stream::MediaTrackConstrains{});
        streamApi->publishStream(handle_USER_1);
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    });
    //Subscribe for Data Track as user_1
    std::vector<stream::StreamSubscription> streamsId;
    EXPECT_NO_THROW({
        auto streamlist = client2.streamApi->listStreams(streamRoomId_1);
        for(auto stream : streamlist) {
            for(auto track : stream.tracks) {
                streamsId.push_back(stream::StreamSubscription{stream.id, track.mid});
            }
        }
    });
    std::string dataToSend = "testing_data";
    auto collector = std::make_shared<PlainDataCollector>();
    EXPECT_NO_THROW({
        client2.streamApi->joinStreamRoom(streamRoomId_1);
        client2.streamApi->addRemoteStreamListener(streamRoomId_1, std::nullopt, collector);
        client2.streamApi->subscribeToRemoteStreams(streamRoomId_1, streamsId);
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    });
    //Send data
    EXPECT_NO_THROW({
        streamApi->sendData(handle_USER_1, core::Buffer::from(dataToSend));
    });
    ASSERT_TRUE(collector->waitForMessages(1, std::chrono::seconds(10)));
    auto messages = collector->messages();
    ASSERT_EQ(messages.size(), 1);
    EXPECT_EQ(messages[0].payload, dataToSend);
    EXPECT_EQ(messages[0].seq, 0);
    EXPECT_EQ(messages[0].statusCode, 0);
}

TEST_F(StreamTest, dataChannel_seq_between_three_users) {
    auto contextId = reader->getString("Context_1.contextId");
    StreamClient client1;
    client1.userId = reader->getString("Login.user_1_id");
    client1.pubKey = reader->getString("Login.user_1_pubKey");
    client1.privKey = reader->getString("Login.user_1_privKey");
    client1.connection = connection;
    client1.eventApi = eventApi;
    client1.streamApi = streamApi;
    auto client2 = createClient(
        reader->getString("Login.user_2_id"),
        reader->getString("Login.user_2_pubKey"),
        reader->getString("Login.user_2_privKey")
    );
    auto client3 = createClient(
        reader->getString("Login.user_3_id"),
        reader->getString("Login.user_3_pubKey"),
        reader->getString("Login.user_3_privKey")
    );

    std::string streamRoomId;

    std::vector<core::UserWithPubKey> roomUsers = {
        core::UserWithPubKey{.userId = client1.userId, .pubKey = client1.pubKey},
        core::UserWithPubKey{.userId = client2.userId, .pubKey = client2.pubKey},
        core::UserWithPubKey{.userId = client3.userId, .pubKey = client3.pubKey},
    };

    EXPECT_NO_THROW({
        streamRoomId = client1.streamApi->createStreamRoom(
            contextId,
            roomUsers,
            roomUsers,
            core::Buffer::from("public"),
            core::Buffer::from("private"),
            std::nullopt
        );
    });
    ASSERT_FALSE(streamRoomId.empty());

    stream::StreamHandle handle1;
    stream::StreamHandle handle2;
    stream::StreamHandle handle3;

    EXPECT_NO_THROW({
        handle1 = publishDataStream(client1.streamApi, streamRoomId);
        handle2 = publishDataStream(client2.streamApi, streamRoomId);
        handle3 = publishDataStream(client3.streamApi, streamRoomId);
    });
    
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    std::map<std::string, std::string> remoteStreamToUserId;
    std::vector<stream::StreamSubscription> client1Subscriptions;
    std::vector<stream::StreamSubscription> client2Subscriptions;
    std::vector<stream::StreamSubscription> client3Subscriptions;
    EXPECT_NO_THROW({
    
        auto streamList = client1.streamApi->listStreams(streamRoomId);
        for(const auto& streamInfo : streamList) {
            for(const auto& track : streamInfo.tracks) {
                if(track.type != "data") {
                    continue;
                }
                auto remoteStreamId = std::to_string(streamInfo.id);
                remoteStreamToUserId[remoteStreamId] = streamInfo.userId;
                stream::StreamSubscription subscription;
                subscription.streamId = streamInfo.id;
                subscription.streamTrackId = track.mid;
                if(streamInfo.userId != client1.userId) {
                    client1Subscriptions.push_back(subscription);
                }
                if(streamInfo.userId != client2.userId) {
                    client2Subscriptions.push_back(subscription);
                }
                if(streamInfo.userId != client3.userId) {
                    client3Subscriptions.push_back(subscription);
                }
            }
        }
    });
    ASSERT_EQ(remoteStreamToUserId.size(), 3);

    auto collector1 = std::make_shared<PlainDataCollector>();
    auto collector2 = std::make_shared<PlainDataCollector>();
    auto collector3 = std::make_shared<PlainDataCollector>();

    EXPECT_NO_THROW({
        client1.streamApi->addRemoteStreamListener(streamRoomId, std::nullopt, collector1);
        client2.streamApi->addRemoteStreamListener(streamRoomId, std::nullopt, collector2);
        client3.streamApi->addRemoteStreamListener(streamRoomId, std::nullopt, collector3);

        client1.streamApi->subscribeToRemoteStreams(streamRoomId, client1Subscriptions);
        client2.streamApi->subscribeToRemoteStreams(streamRoomId, client2Subscriptions);
        client3.streamApi->subscribeToRemoteStreams(streamRoomId, client3Subscriptions);
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    });

    auto expectedPayloads = std::map<std::string, std::vector<std::string>>{
        {client1.userId, {"msg-" + client1.userId + "-0", "msg-" + client1.userId + "-1"}},
        {client2.userId, {"msg-" + client2.userId + "-0", "msg-" + client2.userId + "-1"}},
        {client3.userId, {"msg-" + client3.userId + "-0", "msg-" + client3.userId + "-1"}}
    };

    EXPECT_NO_THROW({
        client1.streamApi->sendData(handle1, core::Buffer::from(expectedPayloads.at(client1.userId)[0]));
        client2.streamApi->sendData(handle2, core::Buffer::from(expectedPayloads.at(client2.userId)[0]));
        client3.streamApi->sendData(handle3, core::Buffer::from(expectedPayloads.at(client3.userId)[0]));
        client1.streamApi->sendData(handle1, core::Buffer::from(expectedPayloads.at(client1.userId)[1]));
        client2.streamApi->sendData(handle2, core::Buffer::from(expectedPayloads.at(client2.userId)[1]));
        client3.streamApi->sendData(handle3, core::Buffer::from(expectedPayloads.at(client3.userId)[1]));
    });

    ASSERT_TRUE(collector1->waitForMessages(4, std::chrono::seconds(15)));
    ASSERT_TRUE(collector2->waitForMessages(4, std::chrono::seconds(15)));
    ASSERT_TRUE(collector3->waitForMessages(4, std::chrono::seconds(15)));

    auto assertCollector = [&](const std::string& receiverUserId, const std::shared_ptr<PlainDataCollector>& collector) {
        auto messages = collector->messages();
        ASSERT_EQ(messages.size(), 4);
        std::map<std::string, std::vector<PlainDataCollector::Message>> groupedBySender;
        for(const auto& message : messages) {
            auto senderIt = remoteStreamToUserId.find(message.trackId);
            ASSERT_NE(senderIt, remoteStreamToUserId.end()) << "Unknown remote stream id " << message.trackId;
            EXPECT_EQ(message.statusCode, 0);
            groupedBySender[senderIt->second].push_back(message);
        }

        ASSERT_EQ(groupedBySender.size(), 2);
        for(const auto& [senderUserId, payloads] : expectedPayloads) {
            if(senderUserId == receiverUserId) {
                continue;
            }
            auto groupedIt = groupedBySender.find(senderUserId);
            ASSERT_NE(groupedIt, groupedBySender.end()) << "Missing messages from " << senderUserId;
            ASSERT_EQ(groupedIt->second.size(), 2);
            EXPECT_EQ(groupedIt->second[0].seq, 0);
            EXPECT_EQ(groupedIt->second[1].seq, 1);
            EXPECT_EQ(groupedIt->second[0].payload, payloads[0]);
            EXPECT_EQ(groupedIt->second[1].payload, payloads[1]);
        }
    };

    assertCollector(client1.userId, collector1);
    assertCollector(client2.userId, collector2);
    assertCollector(client3.userId, collector3);
    
}
