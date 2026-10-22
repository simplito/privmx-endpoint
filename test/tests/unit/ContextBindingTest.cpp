/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * 07A: what reaches the application is bound to the context it asked for, and the UserVerifier is asked about the
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
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/utils/Utils.hpp>

#include "TestHelpers.hpp"

namespace core = privmx::endpoint::core;
namespace event = privmx::endpoint::event;
using privmx::crypto::PrivateKey;

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

} // namespace
