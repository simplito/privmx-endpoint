#include <gtest/gtest.h>
#include "../utils/BaseTest.hpp"
#include "../utils/FalseUserVerifierInterface.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/endpoint/core/VarSerializer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/stream/StreamApiLow.hpp>
#include <privmx/endpoint/stream/StreamVarSerializer.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>
#include <privmx/endpoint/stream/WebRTCInterface.hpp>
#include <libwebrtc.h>
#include <pmx_frame_cryptor.h>

using namespace privmx::endpoint;

class FalseUserVerifierInterface: public virtual core::UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<core::VerificationRequest>& request) override {
        return std::vector<bool>(request.size(), false);
    };
};

enum ConnectionType {
    User1,
    User2,
    Public
};

class FakeWebRTC : public privmx::endpoint::stream::WebRTCInterface 
{
public:
    FakeWebRTC() {}
    ~FakeWebRTC() {}
    std::string createOfferAndSetLocalDescription(const std::string& streamRoomId) override {return "random";}
    std::string createAnswerAndSetDescriptions(const std::string& streamRoomId, const std::string& sdp, const std::string& type) override {return "random";}
    void setAnswerAndSetRemoteDescription(const std::string& streamRoomId, const std::string& sdp, const std::string& type) override {return;}
    virtual void updateSessionId(const std::string& streamRoomId, const int64_t sessionId, const std::string& connectionType) override {return;}
    void close(const std::string& streamRoomId) override {return;}
    void updateKeys(const std::string& streamRoomId, const std::vector<privmx::endpoint::stream::Key>& keys) override {return;}
};

class StreamLowTest : public privmx::test::BaseTest {
protected:
    StreamLowTest() : BaseTest(privmx::test::BaseTestMode::online) {}
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
        eventApi = std::make_shared<event::EventApi>(
            event::EventApi::create(
                *connection
            )
        );
        streamApiLow = std::make_shared<stream::StreamApiLow>(
            stream::StreamApiLow::create(
                *connection,
                *eventApi
            )
        );
    }
    void disconnect() {
        connection->disconnect();
        connection.reset();
        streamApiLow.reset();
        eventApi.reset();
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
        eventApi = std::make_shared<event::EventApi>(
            event::EventApi::create(
                *connection
            )
        );
        streamApiLow = std::make_shared<stream::StreamApiLow>(
            stream::StreamApiLow::create(
                *connection,
                *eventApi
            )
        );
    }
    void customTearDown() override { // tmp segfault fix
        connection.reset();
        streamApiLow.reset();
        reader.reset();
        core::EventQueueImpl::getInstance()->clear();
    }
    std::string fastStreamRoom(const std::string& contextId) {
        return streamApiLow->createStreamRoom(
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
    std::shared_ptr<core::Connection> connection;
    std::shared_ptr<event::EventApi> eventApi;
    std::shared_ptr<stream::StreamApiLow> streamApiLow;
    Poco::Util::IniFileConfiguration::Ptr reader;
    core::VarSerializer _serializer = core::VarSerializer({});
};

TEST_F(StreamLowTest, createStream) {
    // different users and managers
    std::string streamRoomId;
    stream::StreamRoom streamRoom;
    EXPECT_NO_THROW({
        streamRoomId = streamApiLow->createStreamRoom(
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
        streamRoom = streamApiLow->getStreamRoom(
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
        streamRoomId = streamApiLow->createStreamRoom(
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
        streamRoom = streamApiLow->getStreamRoom(
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

TEST_F(StreamLowTest, listStreamRooms_incorrect_input_data) {
    // incorrect contextId
    EXPECT_THROW({
        streamApiLow->listStreamRooms(
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
        streamApiLow->listStreamRooms(
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
        streamApiLow->listStreamRooms(
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
        streamApiLow->listStreamRooms(
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
        streamApiLow->listStreamRooms(
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
        streamApiLow->listStreamRooms(
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
        streamApiLow->listStreamRooms(
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

TEST_F(StreamLowTest, listStreamRooms_correct_input_data) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    auto streamRoomId_2 = fastStreamRoom(reader->getString("Context_1.contextId"));
    auto streamRoomId_3 = fastStreamRoom(reader->getString("Context_1.contextId"));

    core::PagingList<stream::StreamRoom> listStreamRooms;
    // {.skip=4, .limit=1, .sortOrder="desc"}
    EXPECT_NO_THROW({
        listStreamRooms = streamApiLow->listStreamRooms(
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
        listStreamRooms = streamApiLow->listStreamRooms(
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
        listStreamRooms = streamApiLow->listStreamRooms(
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

TEST_F(StreamLowTest, updateStreamRoom_incorrect_data) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    // incorrect streamRoomId
    EXPECT_THROW({
        streamApiLow->updateStreamRoom(
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
        streamApiLow->updateStreamRoom(
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
        streamApiLow->updateStreamRoom(
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
        streamApiLow->updateStreamRoom(
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
        streamApiLow->updateStreamRoom(
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

TEST_F(StreamLowTest, updateStreamRoom_correct_data) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    auto streamRoomId_2 = fastStreamRoom(reader->getString("Context_1.contextId"));
    stream::StreamRoom streamRoom;
    // less users
    EXPECT_NO_THROW({
        streamApiLow->updateStreamRoom(
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
        streamRoom = streamApiLow->getStreamRoom(
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
        streamApiLow->updateStreamRoom(
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
        streamRoom = streamApiLow->getStreamRoom(
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
        streamApiLow->updateStreamRoom(
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
        streamRoom = streamApiLow->getStreamRoom(
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

TEST_F(StreamLowTest, deleteStream) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    // incorrect streamRoomId
    EXPECT_THROW({
        streamApiLow->deleteStreamRoom(
            reader->getString("Context_1.contextId")
        );
    }, core::Exception);
    // as manager
     EXPECT_NO_THROW({
        streamApiLow->deleteStreamRoom(
            streamRoomId_1
        );
    });
    EXPECT_THROW({
        streamApiLow->getStreamRoom(
            streamRoomId_1
        );
    }, core::Exception);
}

TEST_F(StreamLowTest, userValidator_false) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    auto streamRoomId_2 = fastStreamRoom(reader->getString("Context_1.contextId"));
    auto verifier = std::make_shared<core::FalseUserVerifierInterface>();
    connection->setUserVerifier(verifier);
    // getStreamRoom
    EXPECT_NO_THROW({
        auto Stream = streamApiLow->getStreamRoom(
            streamRoomId_1
        );
        EXPECT_FALSE(Stream.statusCode == 0);
    });
    // listStreamRooms
    EXPECT_NO_THROW({
        auto Streams = streamApiLow->listStreamRooms(
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
        streamApiLow->createStreamRoom(
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
        streamApiLow->updateStreamRoom(
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
        streamApiLow->deleteStreamRoom(
            streamRoomId_2
        );
    });
}

TEST_F(StreamLowTest, falseUserVerifierInterface) {
    auto streamRoomId_1 = fastStreamRoom(reader->getString("Context_1.contextId"));
    EXPECT_NO_THROW({
        streamApiLow->updateStreamRoom(
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
        streamListResult = streamApiLow->listStreamRooms(reader->getString("Context_1.contextId"),{.skip=0, .limit=1, .sortOrder="desc"});
    });
    if(streamListResult.readItems.size() == 1) {
        EXPECT_EQ(streamListResult.readItems[0].statusCode, core::UserVerificationFailureException().getCode());
    } else {
        FAIL();
    }
}