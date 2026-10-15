/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/cryptoservice/base/CoreTypes.hpp>

#include <privmx/endpoint/core/crypto/CryptoErrors.hpp>
#include <privmx/endpoint/core/crypto/FormatHash.hpp>
#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

namespace {

cs::BytesView view(const std::string& data) {
    return cs::BytesView(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

std::string str(const cs::Bytes& data) {
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

} // namespace

std::string FormatHash::sha256(const std::string& data) {
    return mapCryptoErrors("FormatHash::sha256", [&] {
        return str(cryptoProvider().digest(cs::Hash::Sha256, view(data)));
    });
}

std::string FormatHash::hmacSha256(const std::string& key, const std::string& data) {
    return mapCryptoErrors("FormatHash::hmacSha256", [&] {
        return str(cryptoProvider().hmac(cs::Hash::Sha256, view(key), view(data)));
    });
}

std::string FormatHash::kdf(const std::string& secret, const std::string& label, std::size_t length) {
    return mapCryptoErrors("FormatHash::kdf", [&] {
        cs::KdfParams params{
            .kdf = cs::Kdf::Kdf, .length = length, .hash = cs::Hash::Sha256, .rounds = 0, .salt = {}, .label = label
        };
        return str(cryptoProvider().derive(params, view(secret)));
    });
}
