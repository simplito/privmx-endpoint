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

std::string FormatHash::sha256(const std::string& data) {
    return mapCryptoErrors("FormatHash::sha256", [&] {
        const cs::Bytes digest = cryptoProvider().digest(
            cs::Hash::Sha256, cs::BytesView(reinterpret_cast<const std::uint8_t*>(data.data()), data.size())
        );
        return std::string(reinterpret_cast<const char*>(digest.data()), digest.size());
    });
}
