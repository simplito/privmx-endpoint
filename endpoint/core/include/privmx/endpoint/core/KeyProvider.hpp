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
    // privmx::utils::List<server::KeyEntrySet> updateKeysList(const utils::List<server::KeyEntrySet>& currentKeysList, const std::string& currentKeyId, const std::vector<UserWithPubKey>& newUsers, const EncKey& key);

private:
    privmx::crypto::PrivateKey _key;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_KEYPROVIDER_HPP_
