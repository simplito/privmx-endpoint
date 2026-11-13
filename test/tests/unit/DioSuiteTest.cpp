/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * The integrity layer's half of the container's algorithm choice.
 *
 * A DIO records the suite its field checksums were made with, which is what lets those checksums
 * follow the container instead of being pinned to SHA-256. The three things that has to be true for:
 *
 *  - the suite survives a round trip, so a reader learns it rather than assuming it;
 *  - a DIO written before the field existed still reads, as SHA-256 — the hash those checksums were
 *    in fact made with;
 *  - the field is inside the signed bytes, so it cannot be rewritten to name a weaker suite.
 *
 * The last one is the point of the whole design and the only one whose failure would be silent: the
 * other two break loudly, this one would just quietly accept a downgrade.
 */

#include <gtest/gtest.h>

#include <functional>
#include <optional>
#include <string>

#include <Poco/JSON/Object.h>

#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp>
#include <privmx/endpoint/core/encryptors/DataInnerEncryptorV4.hpp>

using namespace privmx::endpoint;

namespace {

core::DataIntegrityObject baseDio(const core::PrivateKey& author) {
    return core::DataIntegrityObject{
        .creatorUserId = "alice",
        .creatorPubKey = author.getPublicKey().toBase58DER(),
        .contextId = "ctx1",
        .resourceId = "res1",
        .timestamp = 1700000000,
        .randomId = "rnd1",
        .containerId = std::nullopt,
        .containerResourceId = std::nullopt,
        .bridgeIdentity = std::nullopt
    };
}

core::ExpandedDataIntegrityObject expanded(const core::PrivateKey& author, core::CryptoSuite suite) {
    return core::ExpandedDataIntegrityObject{baseDio(author), 5, {{"publicMeta", suite.hash("payload")}}, suite};
}

// `\x01 | sigLen | signature | json`, the shape `DataInnerEncryptorV4` packs. Packed here by hand
// rather than through the encryptor, whose packer is private — and a bridge rewriting a DIO it was
// handed has no more access to our internals than this does.
std::string packed(const std::string& signature, const std::string& json) {
    std::string out(1, static_cast<char>(1));
    out.append(1, static_cast<char>(signature.size()));
    out.append(signature);
    out.append(json);
    return out;
}

// Edits the DIO's JSON and puts the **original signature** back. Re-signing is deliberately not
// offered: a helper that could re-sign would prove nothing about the signature covering the suite.
std::string rewriteDioJson(const std::string& encoded, const std::function<void(Poco::JSON::Object::Ptr)>& edit) {
    core::DataInnerEncryptorV4 inner;
    const auto parts = inner.extractDataWithSignature(inner.decode(encoded));
    auto json = privmx::utils::Utils::parseJsonObject(parts.data.stdString());
    edit(json);
    return inner.encode(
        core::Buffer::from(packed(parts.signature.stdString(), privmx::utils::Utils::stringifyVar(json)))
    );
}

} // namespace

TEST(DioSuite, TheSuiteSurvivesARoundTrip) {
    core::DIOEncryptorV1 encryptor;
    const core::PrivateKey author = core::PrivateKey::generateRandom();
    for (const core::SuiteId id : core::CryptoSuite::known()) {
        const core::CryptoSuite suite = core::CryptoSuite::forId(id);
        const auto decoded = encryptor.decodeAndVerify(encryptor.signAndEncode(expanded(author, suite), author));
        EXPECT_EQ(decoded.suite.id(), id);
        // And the checksum it carries verifies under the suite it named, not under this build's.
        EXPECT_EQ(decoded.fieldChecksums.at("publicMeta"), decoded.suite.hash("payload"));
    }
}

TEST(DioSuite, EachSuiteLeavesAChecksumOfItsOwnLength) {
    // Otherwise the round trip above would pass with the suite recorded and then ignored.
    const auto sha256 = core::CryptoSuite::forId(core::SuiteId::Aes256GcmSha256);
    const auto sha512 = core::CryptoSuite::forId(core::SuiteId::Aes256GcmSha512);
    EXPECT_EQ(sha256.hash("payload").size(), 32u);
    EXPECT_EQ(sha512.hash("payload").size(), 64u);
}

TEST(DioSuite, ADioFromBeforeTheFieldReadsAsSha256) {
    core::DIOEncryptorV1 encryptor;
    core::DataInnerEncryptorV4 inner;
    const core::PrivateKey author = core::PrivateKey::generateRandom();
    const auto sha256 = core::CryptoSuite::forId(core::SuiteId::Aes256GcmSha256);

    // Signed without the field, the way a client that predates it would — stripping the field from a
    // DIO signed today would only break the signature, and prove nothing about the compatibility rule.
    const std::string today = encryptor.signAndEncode(expanded(author, sha256), author);
    auto dioJson = privmx::utils::Utils::parseJsonObject(
        inner.extractDataWithSignature(inner.decode(today)).data.stdString()
    );
    dioJson->remove("cryptoSuite");
    const std::string reSigned = inner.encode(
        inner.signAndPackDataWithSignature(
            core::Buffer::from(privmx::utils::Utils::stringifyVar(dioJson)), author
        )
    );

    const auto decoded = encryptor.decodeAndVerify(reSigned);
    EXPECT_EQ(decoded.suite.id(), core::SuiteId::Aes256GcmSha256);
    // Which is the suite those checksums really were made with, so they still verify.
    EXPECT_EQ(decoded.fieldChecksums.at("publicMeta"), decoded.suite.hash("payload"));
}

TEST(DioSuite, SECURITY_RewritingTheSuiteBreaksTheSignature) {
    core::DIOEncryptorV1 encryptor;
    const core::PrivateKey author = core::PrivateKey::generateRandom();
    const auto sha512 = core::CryptoSuite::forId(core::SuiteId::Aes256GcmSha512);

    const std::string signed_ = encryptor.signAndEncode(expanded(author, sha512), author);
    ASSERT_EQ(encryptor.decodeAndVerify(signed_).suite.id(), core::SuiteId::Aes256GcmSha512);

    // Control, without which the two expectations below would pass even if the signature covered
    // nothing: a trip through `rewriteDioJson` that changes no field must still verify. If re-serialising
    // the JSON were enough to break the signature, this would fail and the rest would prove nothing.
    const std::string untouched = rewriteDioJson(signed_, [](Poco::JSON::Object::Ptr) {});
    ASSERT_EQ(encryptor.decodeAndVerify(untouched).suite.id(), core::SuiteId::Aes256GcmSha512);

    // A bridge naming the weaker suite, so a reader would verify the checksums with SHA-256.
    const std::string downgraded = rewriteDioJson(signed_, [](Poco::JSON::Object::Ptr dio) {
        dio->set("cryptoSuite", static_cast<int64_t>(core::SuiteId::Aes256GcmSha256));
    });
    EXPECT_THROW(encryptor.decodeAndVerify(downgraded), core::DataIntegrityObjectInvalidSignatureException);

    // And dropping it outright, which would otherwise read as SHA-256 by the compatibility rule above —
    // the rule must not become a way to downgrade a DIO that did name a suite.
    const std::string stripped = rewriteDioJson(signed_, [](Poco::JSON::Object::Ptr dio) {
        dio->remove("cryptoSuite");
    });
    EXPECT_THROW(encryptor.decodeAndVerify(stripped), core::DataIntegrityObjectInvalidSignatureException);
}

TEST(DioSuite, ASuiteThisBuildCannotReadIsRefused) {
    core::DIOEncryptorV1 encryptor;
    const core::PrivateKey author = core::PrivateKey::generateRandom();
    const auto sha256 = core::CryptoSuite::forId(core::SuiteId::Aes256GcmSha256);
    const std::string signed_ = encryptor.signAndEncode(expanded(author, sha256), author);

    // Not a downgrade but a suite from a future build. It fails on the signature first, which is the
    // right order: an unknown suite reaches `forId` only on a DIO that is otherwise genuine.
    const std::string future = rewriteDioJson(signed_, [](Poco::JSON::Object::Ptr dio) {
        dio->set("cryptoSuite", static_cast<int64_t>(0x7f));
    });
    EXPECT_ANY_THROW(encryptor.decodeAndVerify(future));
}
