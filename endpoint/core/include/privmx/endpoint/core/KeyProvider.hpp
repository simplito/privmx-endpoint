/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_KEYPROVIDER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_KEYPROVIDER_HPP_

#include <memory>
#include <privmx/crypto/ecc/PrivateKey.hpp>

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class KeyProvider {
public:
    KeyProvider(const privmx::crypto::PrivateKey& key);
    EncKey generateKey();
    EncKey getKey(const utils::List<server::KeyEntry>& keys, const std::string& keyId);
    privmx::utils::List<server::KeyEntrySet> prepareKeysList(const std::vector<UserWithPubKey>& users,
                                                             const EncKey& key);
    privmx::utils::List<server::KeyEntrySet> prepareOldKeysListForNewUsers(const utils::List<server::KeyEntry>& oldKeys, const std::vector<UserWithPubKey>& users);             

private:
    privmx::crypto::PrivateKey _key;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_KEYPROVIDER_HPP_
