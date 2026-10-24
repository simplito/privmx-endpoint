/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * What reaches the application is bound to the context it asked for, and the UserVerifier is asked about the
 * identity the application is told. A context listing refuses items filed under another context, a context custom
 * event refuses a DIO naming another author or context than its envelope, and an event delivered on a subscription
 * for another context is refused. Emitting an event wraps its key only to keys the verifier vouches for.
 */

#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/EndpointUtils.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/endpoint/core/UserVerifierInterface.hpp>
#include <privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/event/EventApiImpl.hpp>
#include <privmx/endpoint/event/Events.hpp>
#include <privmx/endpoint/event/ServerTypes.hpp>
#include <privmx/endpoint/event/encryptors/event/EventDataEncryptorV5.hpp>
#include <privmx/endpoint/event/encryptors/event/EventDataSchemaMapper.hpp>
#include <privmx/endpoint/inbox/InboxApiImpl.hpp>
#include <privmx/endpoint/inbox/ServerApi.hpp>
#include <privmx/endpoint/kvdb/KvdbApiImpl.hpp>
#include <privmx/endpoint/kvdb/ServerApi.hpp>
#include <privmx/endpoint/store/FileDataProvider.hpp>
#include <privmx/endpoint/store/RequestApi.hpp>
#include <privmx/endpoint/store/ServerApi.hpp>
#include <privmx/endpoint/store/StoreApiImpl.hpp>
#include <privmx/endpoint/stream/ServerApi.hpp>
#include <privmx/endpoint/thread/ServerApi.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/thread/ThreadApiImpl.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/utils/Utils.hpp>

#include "TestHelpers.hpp"

namespace core = privmx::endpoint::core;
namespace event = privmx::endpoint::event;
namespace thread = privmx::endpoint::thread;
namespace store = privmx::endpoint::store;
namespace kvdb = privmx::endpoint::kvdb;
namespace inbox = privmx::endpoint::inbox;
namespace stream = privmx::endpoint::stream;
using privmx::crypto::PrivateKey;

namespace privmx::endpoint::store {
// A read-write handle on `fileId` in store `storeId`, over an empty file, without opening a real one.
struct StoreApiImplTestAccess {
    static std::int64_t readWriteHandle(StoreApiImpl& api, const std::string& storeId, const std::string& fileId) {
        const std::string key(32, 'k');
        FileEncryptionParams params;
        params.fileDecryptionParams = FileDecryptionParams{
            .fileId = fileId, .resourceId = "r", .sizeOnServer = 0, .originalSize = 0, .cipherType = 1,
            .chunkSize = 1024, .key = key, .hmac = privmx::crypto::Crypto::hmacSha256(key, ""), .version = 1
        };
        return api._fileHandleManager
            .createFileReadWriteHandle(
                FileInfo{.contextId = "ctx", .storeId = storeId, .storeResourceId = "", .fileId = fileId, .resourceId = "r"},
                params, 1024, api._userPrivKey, api._connection, api._serverApi, api._chunksCache
            )
            ->getId();
    }
};
} // namespace privmx::endpoint::store

namespace {

const int64_t REFUSED = core::UserVerificationFailureException().getCode();

// The application's verifier: vouches for exactly the (user, key) pairs it was given, and records every request.
class Verifier : public core::UserVerifierInterface {
public:
    std::map<std::string, std::string> keys;
    std::vector<core::VerificationRequest> asked;
    std::vector<bool> verify(const std::vector<core::VerificationRequest>& requests) override {
        std::vector<bool> result;
        for (const auto& request : requests) {
            asked.push_back(request);
            const auto it = keys.find(request.senderId);
            result.push_back(it != keys.end() && it->second == request.senderPubKey);
        }
        return result;
    }
};

// --- context listings ---------------------------------------------------------------------------------------------

struct Served {
    struct Entry {
        std::string keyId;
    };
    std::string contextId;
    std::vector<Entry> data{{"k"}};
};
struct Listed {
    std::string contextId;
    std::string lastModifier;
    int64_t lastModificationDate = 0;
    int64_t statusCode = 0;
};

TEST(ContextBinding, SECURITY_AListedContainerFromAnotherContextIsRefused) {
    // The Bridge files a container of another context into the listing of `ctx-a`: refused before anything of it is
    // checked or its key requested (there is no key provider here, a key request would crash).
    auto impl = std::make_shared<core::ConnectionImpl>();
    const ConnectionOf connection(impl);
    int integrityChecks = 0;
    const auto result = core::DataSchemaMapperUtils::batchValidateDecryptVerifyContainers<Listed>(
        std::vector<Served>{{.contextId = "ctx-b"}, {.contextId = "ctx-a"}}, nullptr, connection,
        [&](const Served&) -> std::pair<uint32_t, std::optional<core::DataIntegrityObject>> {
            ++integrityChecks;
            return {7, std::nullopt}; // the item of the asked context stops here, before any key request
        },
        [](const Served& s) { return core::EncKeyLocation{.contextId = s.contextId, .resourceId = ""}; },
        [](const Served&, const core::DecryptedEncKey&, const std::optional<core::DataIntegrityObject>&)
            -> std::tuple<Listed, core::DataIntegrityObject> { throw std::logic_error("no key to decrypt with"); },
        [](const Served& s, uint32_t code) { return Listed{.contextId = s.contextId, .statusCode = code}; },
        nullptr, std::string("ctx-a")
    );
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].statusCode, REFUSED);
    EXPECT_EQ(result[1].statusCode, 7);
    EXPECT_EQ(integrityChecks, 1) << "only the item of the asked context is checked";
}

// --- context custom events ----------------------------------------------------------------------------------------

// An event `signer` sealed for `recipient` with a DIO naming (`dioUser`, `dioContext`), in an envelope the Bridge
// labels (`envelopeUser`, `envelopeContext`). The envelope's key is the signer's: the DIO key check holds.
event::server::ContextCustomEventData seal(
    const PrivateKey& signer,
    const PrivateKey& recipient,
    const std::string& dioUser,
    const std::string& dioContext,
    const std::string& envelopeUser,
    const std::string& envelopeContext
) {
    const std::string key = privmx::crypto::Crypto::randomBytes(32);
    core::DataIntegrityObject dio{
        .creatorUserId = dioUser,
        .creatorPubKey = signer.getPublicKey().toBase58DER(),
        .contextId = dioContext,
        .resourceId = "",
        .timestamp = privmx::utils::Utils::getNowTimestamp(),
        .randomId = "random-id",
        .containerId = std::nullopt,
        .containerResourceId = std::nullopt,
        .bridgeIdentity = std::nullopt
    };
    event::EventDataEncryptorV5 encryptor;
    const auto encrypted = encryptor.encrypt(
        event::ContextEventDataToEncryptV5{
            {.data = core::Buffer::from("hello"), .type = std::nullopt, .dio = dio}
        },
        signer, key
    );
    event::server::ContextCustomEventData raw;
    raw.id = envelopeContext;
    raw.eventData = encrypted.toJSON();
    raw.key = privmx::crypto::EciesEncryptor::encryptToBase64(recipient.getPublicKey(), key, signer);
    core::server::UserIdentity author;
    author.id = envelopeUser;
    author.pub = signer.getPublicKey().toBase58DER();
    raw.author = author;
    return raw;
}

class ContextEventBinding : public testing::Test {
protected:
    PrivateKey me = PrivateKey::generateRandom();
    PrivateKey carol = PrivateKey::generateRandom();
    std::shared_ptr<core::ConnectionImpl> impl = std::make_shared<core::ConnectionImpl>();
    std::shared_ptr<Verifier> verifier = std::make_shared<Verifier>();
    std::unique_ptr<event::EventDataSchemaMapper> mapper;

    void SetUp() override {
        verifier->keys["carol"] = carol.getPublicKey().toBase58DER();
        impl->setUserVerifier(verifier);
        mapper = std::make_unique<event::EventDataSchemaMapper>(me, ConnectionOf(impl));
    }
};

TEST_F(ContextEventBinding, SECURITY_AnEventIsVerifiedUnderTheAuthorTheApplicationIsTold) {
    // Colluding carol seals an event under her own name and key; the Bridge delivers it as bob's. The verifier,
    // which vouches for carol's key, must not be asked about carol while the application is told "bob".
    const auto relabelled = seal(carol, me, "carol", "ctx-a", "bob", "ctx-a");
    const auto delivered = mapper->decrypt(relabelled);
    EXPECT_EQ(delivered.userId, "bob");
    EXPECT_EQ(delivered.statusCode, REFUSED);
    EXPECT_EQ(mapper->decryptInternal(relabelled).statusCode, REFUSED);
    for (const auto& request : verifier->asked) {
        EXPECT_NE(request.senderId, "carol") << "asked about another identity than the one delivered";
    }

    // Under her own name the same event is carol's, and the verifier is asked about exactly that.
    verifier->asked.clear();
    const auto honest = mapper->decrypt(seal(carol, me, "carol", "ctx-a", "carol", "ctx-a"));
    EXPECT_EQ(honest.statusCode, 0);
    ASSERT_EQ(verifier->asked.size(), 1u);
    EXPECT_EQ(verifier->asked[0].senderId, "carol");
    EXPECT_EQ(verifier->asked[0].contextId, "ctx-a");
}

TEST_F(ContextEventBinding, SECURITY_AnEventIsVerifiedUnderTheContextTheApplicationIsTold) {
    // carol's event of ctx-b, delivered in an envelope of ctx-a.
    const auto relabelled = seal(carol, me, "carol", "ctx-b", "carol", "ctx-a");
    const auto delivered = mapper->decrypt(relabelled);
    EXPECT_EQ(delivered.contextId, "ctx-a");
    EXPECT_EQ(delivered.statusCode, REFUSED);
    EXPECT_EQ(mapper->decryptInternal(relabelled).statusCode, REFUSED);
    EXPECT_TRUE(verifier->asked.empty());
}

// --- subscriptions and emitting, over a fake Bridge ---------------------------------------------------------------

struct Bridge {
    std::vector<std::pair<std::string, event::server::ContextEmitCustomEventModel>> sent; // (sender, as sent)
};

class Gateway : public privmx::privfs::RpcGateway {
public:
    Gateway(Bridge& bridge, std::string userId)
        : RpcGateway(privmx::rpc::AuthorizedConnection::Ptr(), std::nullopt), _bridge(bridge),
          _userId(std::move(userId)) {}

    Poco::Dynamic::Var request(
        const std::string& method,
        Poco::JSON::Object::Ptr params,
        privmx::rpc::MessageSendOptionsEx,
        privmx::utils::CancellationToken::Ptr
    ) override {
        params = overTheWire(params);
        if (method == "context.contextGet") {
            return overTheWire(
                core::server::ContextGetResult{
                    .context = {.userId = _userId, .contextId = params->getValue<std::string>("id")}
                }
                    .toJSON()
            );
        }
        if (method == "subscribeToChannels") {
            core::server::SubscribeToChannelsResult result;
            for (const auto& channel : core::server::SubscribeToChannelsModel::fromJSON(params).channels) {
                result.subscriptions.push_back({.subscriptionId = "sub:" + channel, .channel = channel});
            }
            return overTheWire(result.toJSON());
        }
        if (method == "unsubscribeFromChannels") {
            return Poco::Dynamic::Var();
        }
        if (method == "context.contextSendCustomEvent") {
            _bridge.sent.emplace_back(_userId, event::server::ContextEmitCustomEventModel::fromJSON(params));
            return Poco::Dynamic::Var();
        }
        throw std::runtime_error("the fake bridge has no " + method);
    }
    bool isConnected() override { return true; }

private:
    Bridge& _bridge;
    std::string _userId;
};

struct Client {
    PrivateKey key = PrivateKey::generateRandom();
    std::shared_ptr<core::ConnectionImpl> impl = std::make_shared<core::ConnectionImpl>();
    std::shared_ptr<Verifier> verifier = std::make_shared<Verifier>();
    core::Connection connection;
    event::EventApi events;

    Client(Bridge& bridge, const std::string& userId) {
        impl->setUserVerifier(verifier);
        impl->connectOver(new Gateway(bridge, userId), key);
        connection = ConnectionOf(impl);
        events = event::EventApi::create(connection);
    }
    core::UserWithPubKey as(const std::string& userId) const {
        return {.userId = userId, .pubKey = key.getPublicKey().toBase58DER()};
    }
};

class ContextEventApi : public testing::Test {
protected:
    Bridge bridge;
    std::unique_ptr<Client> alice, bob;

    void SetUp() override {
        core::EventQueueImpl::getInstance()->clear();
        alice = std::make_unique<Client>(bridge, "alice");
        bob = std::make_unique<Client>(bridge, "bob");
        alice->verifier->keys["bob"] = bob->key.getPublicKey().toBase58DER();
        bob->verifier->keys["alice"] = alice->key.getPublicKey().toBase58DER();
    }
    void TearDown() override {
        alice.reset();
        bob.reset();
        core::EventQueueImpl::getInstance()->clear();
    }

    // What alice gets for bob's last event of `eventContext`, the Bridge delivering it on her subscription to
    // `subscribedContext`.
    event::ContextCustomEventData deliver(const std::string& eventContext, const std::string& subscribedContext) {
        const auto subscription = alice->events.subscribeFor(
            {alice->events.buildSubscriptionQuery("chat", event::EventSelectorType::CONTEXT_ID, subscribedContext)}
        );
        const auto& [sender, sent] = bridge.sent.back();
        event::server::ContextCustomEventData raw;
        raw.id = eventContext;
        raw.eventData = sent.data;
        raw.key = sent.users.at(0).key;
        core::server::UserIdentity author;
        author.id = sender;
        author.pub = bob->key.getPublicKey().toBase58DER();
        raw.author = author;
        alice->impl->getEventMiddleware()->emitNotificationEvent(
            "custom", core::NotificationEvent{
                          .source = core::EventSource::SERVER,
                          .type = "custom",
                          .data = overTheWire(raw.toJSON()),
                          .version = 1,
                          .timestamp = 1,
                          .subscriptions = subscription
                      }
        );
        const auto delivered = event::Events::extractContextCustomEvent(nextEvent("contextCustom")).data;
        alice->events.unsubscribeFrom(subscription);
        return delivered;
    }
};

TEST_F(ContextEventApi, SECURITY_AnEventFromAnotherContextThanSubscribedIsRefused) {
    bob->events.emitEvent("ctx-b", {alice->as("alice")}, "chat", core::Buffer::from("hello"));
    EXPECT_EQ(deliver("ctx-b", "ctx-a").statusCode, REFUSED) << "a ctx-b event on a ctx-a subscription";
    EXPECT_EQ(deliver("ctx-b", "ctx-b").statusCode, 0);
}

TEST_F(ContextEventApi, SECURITY_AnEventKeyIsNeverWrappedToAKeyTheVerifierRefuses) {
    // A key listed for alice that bob's verifier does not vouch for (a substituted one, as far as bob can tell).
    const auto substituted = core::UserWithPubKey{
        .userId = "alice", .pubKey = PrivateKey::generateRandom().getPublicKey().toBase58DER()
    };
    try {
        bob->events.emitEvent("ctx-a", {substituted}, "chat", core::Buffer::from("hello"));
        ADD_FAILURE() << "emitted to a refused key";
    } catch (const core::Exception& e) { EXPECT_EQ(e.getCode(), REFUSED); }
    EXPECT_TRUE(bridge.sent.empty());
    EXPECT_NO_THROW(bob->events.emitEvent("ctx-a", {alice->as("alice")}, "chat", core::Buffer::from("hello")));
    EXPECT_EQ(bridge.sent.size(), 1u);
}

TEST(ConnectionState, AdoptPreviousIdentityNeedsAConnection) {
    // Never connected: no Bridge to name the slot after, no current key to compare against.
    ConnectionOf connection(std::make_shared<core::ConnectionImpl>());
    EXPECT_THROW(connection.adoptPreviousIdentity(PrivateKey::generateRandom().toWIF()), core::NotConnectedException);
}

// --- container identity (M1) --------------------------------------------------------------------------------------

// Answers each method with what the test put in `answers`; records what was asked.
class Answering : public privmx::privfs::RpcGateway {
public:
    std::map<std::string, Poco::Dynamic::Var> answers;
    std::vector<std::string> asked;
    Answering() : RpcGateway(privmx::rpc::AuthorizedConnection::Ptr(), std::nullopt) {}
    Poco::Dynamic::Var request(
        const std::string& method,
        Poco::JSON::Object::Ptr,
        privmx::rpc::MessageSendOptionsEx,
        privmx::utils::CancellationToken::Ptr
    ) override {
        asked.push_back(method);
        const auto it = answers.find(method);
        if (it == answers.end()) {
            throw std::runtime_error("the fake bridge has no " + method);
        }
        return overTheWire(it->second);
    }
    bool isConnected() override { return true; }
};

TEST(ContextBinding, SECURITY_AContainerServedUnderAnotherIdThanAskedIsRefused) {
    // The Bridge answers a read of container "a" with container "b" the user also belongs to: whatever the caller
    // then writes would go under b's key, read by b's members. Every read naming its container checks the answer.
    auto* answering = new Answering();
    const privmx::privfs::RpcGateway::Ptr gateway = answering;
    auto& bridge = *answering;
    thread::ServerApi threads(gateway);
    store::ServerApi stores(gateway);
    kvdb::ServerApi kvdbs(gateway);
    inbox::ServerApi inboxes(gateway);
    stream::ServerApi streams(gateway);
    struct Case {
        std::string method;
        std::function<Poco::Dynamic::Var(const std::string& servedId)> answer;
        std::function<void()> ask; // asks for container "a"
    };
    const std::vector<Case> cases{
        {"thread.threadGet",
         [](const std::string& id) {
             thread::server::ThreadGetResult r;
             r.thread.id = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] { threads.threadGet({.threadId = "a", .type = std::nullopt}); }},
        {"thread.threadMessagesGet",
         [](const std::string& id) {
             thread::server::ThreadMessagesGetResult r;
             r.thread.id = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] {
             thread::server::ThreadMessagesGetModel m;
             m.threadId = "a";
             threads.threadMessagesGet(m);
         }},
        {"store.storeGet",
         [](const std::string& id) {
             store::server::StoreGetResult r;
             r.store.id = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] { stores.storeGet({.storeId = "a", .type = std::nullopt}); }},
        {"store.storeFileList",
         [](const std::string& id) {
             store::server::StoreFileListResult r;
             r.store.id = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] {
             store::server::StoreFileListModel m;
             m.storeId = "a";
             stores.storeFileList(m);
         }},
        {"store.storeFileGetMany",
         [](const std::string& id) {
             store::server::StoreFileGetManyResult r;
             r.store.id = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] { stores.storeFileGetMany({.storeId = "a", .fileIds = {}, .failOnError = false}); }},
        {"store.storeFileGet", // a file of store "a", served with store `id`'s keys
         [](const std::string& id) {
             store::server::StoreFileGetResult r;
             r.file.id = "f";
             r.file.storeId = "a";
             r.store.id = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] { stores.storeFileGet({.fileId = "f"}); }},
        {"store.storeFileGet", // another file than "f" (`id` "a" names the file asked for here)
         [](const std::string& id) {
             store::server::StoreFileGetResult r;
             r.file.id = id == "a" ? "f" : "g";
             r.file.storeId = "s";
             r.store.id = "s";
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] { stores.storeFileGet({.fileId = "f"}); }},
        {"kvdb.kvdbGet",
         [](const std::string& id) {
             kvdb::server::KvdbGetResult r;
             r.kvdb.id = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] { kvdbs.kvdbGet({.kvdbId = "a", .type = std::nullopt}); }},
        {"kvdb.kvdbListEntries",
         [](const std::string& id) {
             kvdb::server::KvdbListEntriesResult r;
             r.kvdb.id = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] {
             kvdb::server::KvdbListEntriesModel m;
             m.kvdbId = "a";
             kvdbs.kvdbListEntries(m);
         }},
        {"kvdb.kvdbListKeys",
         [](const std::string& id) {
             kvdb::server::KvdbListKeysResult r;
             r.kvdb.id = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] {
             kvdb::server::KvdbListKeysModel m;
             m.kvdbId = "a";
             kvdbs.kvdbListKeys(m);
         }},
        {"kvdb.kvdbEntryGet",
         [](const std::string& id) {
             kvdb::server::KvdbEntryGetResult r;
             r.kvdbEntry.kvdbId = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] { kvdbs.kvdbEntryGet({.kvdbId = "a", .kvdbEntryKey = "k"}); }},
        {"kvdb.kvdbEntryFind",
         [](const std::string& id) {
             kvdb::server::KvdbEntryFindResult r;
             r.kvdbEntry = kvdb::server::KvdbEntryInfo{};
             r.kvdbEntry->kvdbId = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] { kvdbs.kvdbEntryFind({.kvdbId = "a", .kvdbEntryKey = "k"}); }},
        {"inbox.inboxGet",
         [](const std::string& id) {
             inbox::server::InboxGetResult r;
             r.inbox.id = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] { inboxes.inboxGet({.id = "a", .type = std::nullopt}); }},
        {"inbox.inboxGetPublicView",
         [](const std::string& id) {
             inbox::server::InboxGetPublicViewResult r;
             r.inboxId = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] { inboxes.inboxGetPublicView({.id = "a", .type = std::nullopt}); }},
        {"stream.streamRoomGet",
         [](const std::string& id) {
             stream::server::StreamRoomGetResult r;
             r.streamRoom.id = id;
             return Poco::Dynamic::Var(r.toJSON());
         },
         [&] { streams.streamRoomGet({.id = "a", .type = std::nullopt}); }},
    };
    for (const auto& c : cases) {
        bridge.answers[c.method] = c.answer("b");
        EXPECT_THROW(c.ask(), core::ContainerMismatchException) << c.method << " served another container";
        bridge.answers[c.method] = c.answer("a");
        EXPECT_NO_THROW(c.ask()) << c.method << " refused the container it asked for";
    }
}

TEST(ContextBinding, SECURITY_ASyncedFileServedInAnotherStoreIsRefused) {
    // A read-write handle on file "f" of store `opened`; the re-read at sync serves "f" in store "b" (with b's keys,
    // consistently): nothing of it may reach the handle. A handle with no store recorded is refused too, never let
    // through for want of a value to compare.
    for (const std::string opened : {"a", ""}) {
        auto* answering = new Answering();
        const privmx::privfs::RpcGateway::Ptr gateway = answering;
        auto& bridge = *answering;
        store::server::StoreFileGetResult file;
        file.file.id = "f";
        file.file.storeId = "b";
        file.store.id = "b";
        bridge.answers["store.storeFileGet"] = file.toJSON();
        store::server::StoreFileReadResult checksums; // an empty file: no chunk checksums
        bridge.answers["store.storeFileRead"] = checksums.toJSON();
        const PrivateKey key = PrivateKey::generateRandom();
        auto impl = std::make_shared<core::ConnectionImpl>();
        impl->connectOver(gateway, key);
        const ConnectionOf connection(impl);
        const auto serverApi = std::make_shared<store::ServerApi>(gateway);
        store::StoreApiImpl api(
            impl->getKeyProvider(), serverApi, "", key, std::make_shared<store::RequestApi>(gateway),
            std::make_shared<store::FileDataProvider>(serverApi), impl->getEventMiddleware(), impl->getHandleManager(),
            connection, 1024
        );
        const std::int64_t handle = store::StoreApiImplTestAccess::readWriteHandle(api, opened, "f");
        try {
            api.syncFile(handle);
            ADD_FAILURE() << "synced, opened on store \"" << opened << "\"";
        } catch (const core::ContainerMismatchException& e) {
            EXPECT_NE(std::string(e.what()).find("asked=" + opened + " served=b"), std::string::npos) << e.what();
        }
    }
}

TEST(ContextBinding, SECURITY_AnEmptyIdNamesNoContainer) {
    EXPECT_THROW(core::EndpointUtils::assertServedId("", ""), core::ContainerMismatchException);
    EXPECT_THROW(core::EndpointUtils::assertServedId("a", ""), core::ContainerMismatchException);
    EXPECT_THROW(core::EndpointUtils::assertServedId("", "a"), core::ContainerMismatchException);
    EXPECT_NO_THROW(core::EndpointUtils::assertServedId("a", "a"));
}

TEST(ContextBinding, SECURITY_AListedContainerRefusedForItsContextLeavesNoKeysInTheCache) {
    // Cached first and checked after, a container of another context listed under ctx-a had its keys used by the
    // next write to it without a fresh read. Only items that pass validation and the context check are cached.
    auto* answering = new Answering();
    const privmx::privfs::RpcGateway::Ptr gateway = answering;
    auto& bridge = *answering;
    thread::server::ThreadInfo listed;
    listed.id = "t";
    listed.contextId = "ctx-b";
    listed.keyId = "k";
    thread::server::Thread2DataEntry entry;
    entry.keyId = "k";
    entry.data = std::string("x");
    listed.data = {entry};
    thread::server::ThreadListResult page;
    page.threads = {listed};
    page.count = 1;
    bridge.answers["thread.threadList"] = page.toJSON();

    const PrivateKey key = PrivateKey::generateRandom();
    auto impl = std::make_shared<core::ConnectionImpl>();
    impl->connectOver(gateway, key);
    const ConnectionOf connection(impl);
    thread::ThreadApiImpl api(gateway, key, impl->getKeyProvider(), "", impl->getEventMiddleware(), connection);
    const auto threads = api.listThreads("ctx-a", {.skip = 0, .limit = 10, .sortOrder = "desc"});
    ASSERT_EQ(threads.readItems.size(), 1u);
    EXPECT_EQ(threads.readItems[0].statusCode, REFUSED);
    bridge.asked.clear();
    EXPECT_ANY_THROW(api.sendMessage("t", core::Buffer::from(""), core::Buffer::from(""), core::Buffer::from("")));
    EXPECT_NE(std::find(bridge.asked.begin(), bridge.asked.end(), "thread.threadGet"), bridge.asked.end())
        << "the refused container's keys were taken from the cache";
}

// A module API that also says whether the keys of a container come from its cache (nothing asked) or a read.
template<typename Api>
struct Probe : Api {
    using Api::Api;
    void keysOf(const std::string& id) {
        try {
            this->getModuleKeys(id);
        } catch (...) {} // the fake bridge answers no read: only whether it was asked counts
    }
};

// A container of ctx-b listed under ctx-a: refused, and its keys must not reach the cache.
template<typename Info>
Info listedInAnotherContext() {
    Info listed;
    listed.id = "t";
    listed.contextId = "ctx-b";
    listed.keyId = "k";
    return listed;
}

TEST(ContextBinding, SECURITY_AListedStoreKvdbOrInboxRefusedForItsContextLeavesNoKeysInTheCache) {
    // The thread case above, for every other module that caches a listing's keys.
    auto* answering = new Answering();
    const privmx::privfs::RpcGateway::Ptr gateway = answering;
    auto& bridge = *answering;
    const PrivateKey key = PrivateKey::generateRandom();
    auto impl = std::make_shared<core::ConnectionImpl>();
    impl->connectOver(gateway, key);
    ConnectionOf connection(impl);
    const core::PagingQuery page{.skip = 0, .limit = 10, .sortOrder = "desc"};
    const auto asked = [&](const std::string& method) {
        return std::find(bridge.asked.begin(), bridge.asked.end(), method) != bridge.asked.end();
    };
    {
        auto listed = listedInAnotherContext<store::server::Store>();
        store::server::StoreDataEntry entry;
        entry.keyId = "k";
        entry.data = std::string("x");
        listed.data = {entry};
        store::server::StoreListResult result;
        result.stores = {listed};
        result.count = 1;
        bridge.answers["store.storeList"] = result.toJSON();
        const auto serverApi = std::make_shared<store::ServerApi>(gateway);
        Probe<store::StoreApiImpl> api(
            impl->getKeyProvider(), serverApi, "", key, std::make_shared<store::RequestApi>(gateway),
            std::make_shared<store::FileDataProvider>(serverApi), impl->getEventMiddleware(), impl->getHandleManager(),
            connection, 1024
        );
        const auto stores = api.listStores("ctx-a", page);
        ASSERT_EQ(stores.readItems.size(), 1u);
        EXPECT_EQ(stores.readItems[0].statusCode, REFUSED);
        bridge.asked.clear();
        api.keysOf("t");
        EXPECT_TRUE(asked("store.storeGet")) << "the refused store's keys were taken from the cache";
    }
    {
        auto listed = listedInAnotherContext<kvdb::server::KvdbInfo>();
        kvdb::server::KvdbDataEntry entry;
        entry.keyId = "k";
        entry.data = std::string("x");
        listed.data = {entry};
        kvdb::server::KvdbListResult result;
        result.kvdbs = {listed};
        result.count = 1;
        bridge.answers["kvdb.kvdbList"] = result.toJSON();
        Probe<kvdb::KvdbApiImpl> api(gateway, key, impl->getKeyProvider(), "", impl->getEventMiddleware(), connection);
        const auto kvdbs = api.listKvdbs("ctx-a", page);
        ASSERT_EQ(kvdbs.readItems.size(), 1u);
        EXPECT_EQ(kvdbs.readItems[0].statusCode, REFUSED);
        bridge.asked.clear();
        api.keysOf("t");
        EXPECT_TRUE(asked("kvdb.kvdbGet")) << "the refused kvdb's keys were taken from the cache";
    }
    {
        auto listed = listedInAnotherContext<inbox::server::InboxInfo>();
        inbox::server::InboxDataEntry entry;
        entry.keyId = "k";
        listed.data = {entry};
        inbox::server::InboxListResult result;
        result.inboxes = {listed};
        result.count = 1;
        bridge.answers["inbox.inboxList"] = result.toJSON();
        auto threads = thread::ThreadApi::create(connection);
        auto stores = store::StoreApi::create(connection);
        Probe<inbox::InboxApiImpl> api(
            connection, threads, stores, impl->getKeyProvider(), std::make_shared<inbox::ServerApi>(gateway),
            std::make_shared<store::RequestApi>(gateway), "", key, impl->getEventMiddleware(), impl->getHandleManager(),
            1024
        );
        const auto inboxes = api.listInboxes("ctx-a", page);
        ASSERT_EQ(inboxes.readItems.size(), 1u);
        EXPECT_EQ(inboxes.readItems[0].statusCode, REFUSED);
        bridge.asked.clear();
        api.keysOf("t");
        EXPECT_TRUE(asked("inbox.inboxGet")) << "the refused inbox's keys were taken from the cache";
    }
}

} // namespace
