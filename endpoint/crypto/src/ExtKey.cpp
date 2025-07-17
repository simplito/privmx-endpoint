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
#include <privmx/endpoint/core/ExceptionConverter.hpp>

using namespace privmx::endpoint::crypto;


ExtKey ExtKey::fromSeed(const core::Buffer& seed) {
    try {
        return ExtKey(privmx::crypto::ExtKey::fromSeed(seed.stdString()));
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

ExtKey ExtKey::fromBase58(const std::string& base58) {
    try {
        return ExtKey(privmx::crypto::ExtKey::fromBase58(base58));
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

ExtKey ExtKey::generateRandom() {
    try {
        return ExtKey(privmx::crypto::ExtKey::generateRandom());
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

ExtKey::ExtKey() {}

ExtKey::ExtKey(const privmx::crypto::ExtKey& impl) : _impl(std::make_shared<privmx::crypto::ExtKey>(impl)) {}

// ExtKey::ExtKey(const std::string& key, const std::string& chain_code, bool private_key) 
//     : _impl(std::make_shared<privmx::crypto::ExtKey>(key, chain_code, private_key)) {}

// ExtKey::ExtKey(const std::string& key, const std::string& chain_code, bool private_key, uint8_t depth, uint32_t parent_fingerprint, uint32_t index)
//     : _impl(std::make_shared<privmx::crypto::ExtKey>(key, chain_code, private_key, depth, parent_fingerprint, index)) {}

ExtKey ExtKey::derive(uint32_t index) const {
    try {
        return ExtKey(_impl->derive(index));
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

ExtKey ExtKey::deriveHardened(uint32_t index) const {
    try {
        return ExtKey(_impl->deriveHardened(index));
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string ExtKey::getPrivatePartAsBase58() const {
    try {
        return _impl->getPrivatePartAsBase58();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string ExtKey::getPublicPartAsBase58() const {
    try {
        return _impl->getPublicPartAsBase58();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string ExtKey::getPrivateKey() const {
    try {
        return _impl->getPrivateKey().toWIF();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string ExtKey::getPublicKey() const {
    try {
        return _impl->getPublicKeyAsBase58();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

privmx::endpoint::core::Buffer ExtKey::getPrivateEncKey() const {
    try {
        return privmx::endpoint::core::Buffer::from(_impl->getPrivateEncKey());
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

std::string ExtKey::getPublicKeyAsBase58Address() const {
    try {
        return _impl->getPublicKeyAsBase58Address();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

privmx::endpoint::core::Buffer ExtKey::getChainCode() const {
    try {
        return privmx::endpoint::core::Buffer::from(_impl->getChainCode());
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool ExtKey::verifyCompactSignatureWithHash(const privmx::endpoint::core::Buffer& message, const privmx::endpoint::core::Buffer& signature) const {
    try {
        return _impl->verifyCompactSignatureWithHash(message.stdString(), signature.stdString());
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

bool ExtKey::isPrivate() const {
    try {
        return _impl->isPrivate();
    } catch (const privmx::utils::PrivmxException& e) {
        core::ExceptionConverter::rethrowAsCoreException(e);
        throw core::Exception("ExceptionConverter rethrow error");
    }
}

