/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include "privmx/endpoint/core/LocalSeal.hpp"

#include "privmx/endpoint/core/BigEndian.hpp"
#include "privmx/endpoint/core/crypto/FormatHash.hpp"

using namespace privmx::endpoint::core;

LocalSeal::LocalSeal(
    const PrivateKey& identity,
    const std::string& label,
    std::uint8_t version,
    const std::string& storeKey
)
    : _identity(identity), _label(label), _version(version), _storeKey(storeKey) {}

std::string LocalSeal::tagOf(const std::string& body) const {
    const std::string key = FormatHash::kdf(_identity.getPrivateEncKey(), _label, 32);
    std::string preimage;
    bigendian::putU8(preimage, _version);
    bigendian::putLp(preimage, _storeKey);
    preimage += body;
    return FormatHash::hmacSha256(key, preimage);
}

bool LocalSeal::equalInConstantTime(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

std::string LocalSeal::seal(const std::string& body) const {
    std::string blob;
    bigendian::putU8(blob, _version);
    blob += body;
    blob += tagOf(body);
    return blob;
}

std::optional<std::string> LocalSeal::open(const std::string& blob) const {
    if (blob.size() < 1 + TAG_SIZE || static_cast<std::uint8_t>(blob[0]) != _version) {
        return std::nullopt;
    }
    std::string body = blob.substr(1, blob.size() - 1 - TAG_SIZE);
    if (!equalInConstantTime(blob.substr(blob.size() - TAG_SIZE), tagOf(body))) {
        return std::nullopt;
    }
    return body;
}

bool LocalSeal::update(
    PinStoreInterface& store,
    const std::function<std::string(const std::optional<std::string>&)>& merge
) const {
    for (int attempt = 0; attempt < CAS_ATTEMPTS; ++attempt) {
        const std::string loaded = store.load(_storeKey).stdString();
        const std::optional<std::string> body = loaded.empty() ? std::nullopt : open(loaded);
        const std::string blob = seal(merge(body));
        if (store.save(_storeKey, Buffer::from(blob), Buffer::from(loaded))) {
            return true;
        }
    }
    return false;
}
