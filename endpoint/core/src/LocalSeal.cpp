/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include "privmx/endpoint/core/LocalSeal.hpp"

#include <privmx/crypto/Crypto.hpp>

#include "privmx/endpoint/core/BigEndian.hpp"

using namespace privmx::endpoint::core;

namespace {

constexpr std::size_t TAG_SIZE = 32;
// ponytail: 8 compare-and-swap attempts; a store contended harder than that fails the save (logged, retried later).
constexpr int CAS_ATTEMPTS = 8;

std::string tagOf(
    const privmx::crypto::PrivateKey& identity,
    const std::string& label,
    std::uint8_t version,
    const std::string& storeKey,
    const std::string& body
) {
    const std::string key = privmx::crypto::Crypto::kdf(32, identity.getPrivateEncKey(), label);
    std::string preimage;
    bigendian::putU8(preimage, version);
    bigendian::putLp(preimage, storeKey);
    preimage += body;
    return privmx::crypto::Crypto::hmacSha256(key, preimage);
}

bool equalInConstantTime(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

} // namespace

std::string privmx::endpoint::core::sealLocal(
    const crypto::PrivateKey& identity,
    const std::string& label,
    std::uint8_t version,
    const std::string& storeKey,
    const std::string& body
) {
    std::string blob;
    bigendian::putU8(blob, version);
    blob += body;
    blob += tagOf(identity, label, version, storeKey, body);
    return blob;
}

std::optional<std::string> privmx::endpoint::core::openLocal(
    const crypto::PrivateKey& identity,
    const std::string& label,
    std::uint8_t version,
    const std::string& storeKey,
    const std::string& blob
) {
    if (blob.size() < 1 + TAG_SIZE || static_cast<std::uint8_t>(blob[0]) != version) {
        return std::nullopt;
    }
    std::string body = blob.substr(1, blob.size() - 1 - TAG_SIZE);
    if (!equalInConstantTime(blob.substr(blob.size() - TAG_SIZE), tagOf(identity, label, version, storeKey, body))) {
        return std::nullopt;
    }
    return body;
}

bool privmx::endpoint::core::updateSealed(
    PinStoreInterface& store,
    const crypto::PrivateKey& identity,
    const std::string& storeKey,
    const std::string& label,
    std::uint8_t version,
    const std::function<std::string(const std::optional<std::string>&)>& merge,
    std::string* sealed
) {
    for (int attempt = 0; attempt < CAS_ATTEMPTS; ++attempt) {
        const std::string loaded = store.load(storeKey).stdString();
        const std::optional<std::string> body = loaded.empty() ? std::nullopt
                                                                : openLocal(identity, label, version, storeKey, loaded);
        const std::string blob = sealLocal(identity, label, version, storeKey, merge(body));
        if (store.save(storeKey, Buffer::from(blob), Buffer::from(loaded))) {
            if (sealed != nullptr) {
                *sealed = blob;
            }
            return true;
        }
    }
    return false;
}
