/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/crypto/ExtKey.hpp"
#include <privmx/crypto/ecc/ExtKey.hpp>

using namespace privmx::endpoint::crypto;


ExtKey ExtKey::fromSeed(const core::Buffer& seed) {
    return ExtKey(privmx::crypto::ExtKey::fromSeed(seed.stdString()));
}

ExtKey ExtKey::fromBase58(const std::string& base58) {
    return ExtKey(privmx::crypto::ExtKey::fromBase58(base58));
}

ExtKey ExtKey::generateRandom() {
    return ExtKey(privmx::crypto::ExtKey::generateRandom());
}

ExtKey::ExtKey() {}

ExtKey::ExtKey(const privmx::crypto::ExtKey& impl) : _impl(std::make_shared<privmx::crypto::ExtKey>(impl)) {}

// ExtKey::ExtKey(const std::string& key, const std::string& chain_code, bool private_key) 
//     : _impl(std::make_shared<privmx::crypto::ExtKey>(key, chain_code, private_key)) {}

// ExtKey::ExtKey(const std::string& key, const std::string& chain_code, bool private_key, uint8_t depth, uint32_t parent_fingerprint, uint32_t index)
//     : _impl(std::make_shared<privmx::crypto::ExtKey>(key, chain_code, private_key, depth, parent_fingerprint, index)) {}

ExtKey ExtKey::derive(uint32_t index) const {
    return ExtKey(_impl->derive(index));
}

ExtKey ExtKey::deriveHardened(uint32_t index) const {
    return ExtKey(_impl->deriveHardened(index));
}

std::string ExtKey::getPrivatePartAsBase58() const {
    return _impl->getPrivatePartAsBase58();
}

std::string ExtKey::getPublicPartAsBase58() const {
    return _impl->getPublicPartAsBase58();
}

std::string ExtKey::getPrivateKey() const {
    return _impl->getPrivateKey().toWIF();
}

std::string ExtKey::getPublicKey() const {
    return _impl->getPublicKeyAsBase58();
}

privmx::endpoint::core::Buffer ExtKey::getPrivateEncKey() const {
    return privmx::endpoint::core::Buffer::from(_impl->getPrivateEncKey());
}

std::string ExtKey::getPublicKeyAsBase58Address() const {
    return _impl->getPublicKeyAsBase58Address();
}

privmx::endpoint::core::Buffer ExtKey::getChainCode() const {
    return privmx::endpoint::core::Buffer::from(_impl->getChainCode());
}

bool ExtKey::verifyCompactSignatureWithHash(const privmx::endpoint::core::Buffer& message, const privmx::endpoint::core::Buffer& signature) const {
    return _impl->verifyCompactSignatureWithHash(message.stdString(), signature.stdString());
}

bool ExtKey::isPrivate() const {
    return _impl->isPrivate();
}

