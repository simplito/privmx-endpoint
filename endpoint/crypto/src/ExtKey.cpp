/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Extended keys on pmx-crypto.
 *
 * The derivation is BIP-32 and unchanged — `ExtKeyBip32VectorsTest` pins the specification's own
 * chain codes and private keys across hardened and normal steps, including the two vectors whose
 * master key has a leading zero byte.
 *
 * The **serialisation is not** BIP-32 any more. `getPrivatePartAsBase58` used to emit `xprv…` and
 * now emits pmx-crypto's envelope, which carries the algorithms and can hold a composed identity —
 * something BIP-32's format, with its single key and no algorithm field, cannot express. That is why
 * the vectors check key material rather than the base58 string: the cryptography is still the
 * specification's, the container is not.
 */

#include "privmx/endpoint/crypto/ExtKey.hpp"

#include <cstdint>

#include <privmx/cryptoservice/base/CoreInterfaces.hpp>
#include <privmx/cryptoservice/base/CoreTypes.hpp>
#include <privmx/cryptoservice/base/Exceptions.hpp>

#include <privmx/crypto/pmxcrypto/ProviderAccess.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>

namespace cs = privmx::cryptoservice;

using namespace privmx::endpoint::crypto;

namespace {

cs::BytesView view(const std::string& data) {
    return cs::BytesView(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

std::string str(const cs::Bytes& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

cs::ICryptoProvider& provider() {
    return privmx::crypto::pmximpl::cryptoProvider();
}

/// The curve and formats the old stack used, which this type is still specified in terms of.
constexpr cs::AsymAlg ALG = cs::AsymAlg::PrivmxSecp256k1;

/**
 * Runs an operation, turning pmx-crypto's failures into the exception type callers expect.
 *
 * `privmx::utils::PrivmxException` is still caught: the operations below reach `core::PrivateKey`
 * and friends, which raise it.
 */
template<class Operation>
auto guarded(Operation&& operation) -> decltype(operation()) {
    try {
        return operation();
    } catch (const privmx::utils::PrivmxException& e) {
        privmx::endpoint::core::ExceptionConverter::rethrowAsCoreException(e);
        throw privmx::endpoint::core::Exception("ExceptionConverter rethrow error");
    } catch (const cs::Exception& e) {
        throw privmx::endpoint::core::Exception(std::string("ExtKey: ") + e.what());
    }
}

} // namespace

ExtKey ExtKey::fromSeed(const core::Buffer& seed) {
    return guarded([&] { return ExtKey(provider().extKeyFromSeed(view(seed.stdString()), ALG), true); });
}

ExtKey ExtKey::fromBase58(const std::string& base58) {
    return guarded([&]() -> ExtKey {
        auto key = provider().importExtKey(view(base58), cs::KeyFormat::Base58);
        // Whether the imported key carries a private part decides what may be asked of it. There is
        // no accessor for that, so it is probed once here rather than at every call site: asking a
        // public-only key for its private half is exactly what this answers.
        bool isPrivate = true;
        try {
            key->privateKey(cs::KeyUsageScheme::Sign);
        } catch (const cs::Exception&) {
            isPrivate = false;
        }
        return ExtKey(key, isPrivate);
    });
}

ExtKey ExtKey::generateRandom() {
    return guarded([&] {
        // A BIP-32 master key is made from a seed, and 64 bytes is the length the specification
        // recommends; the old implementation drew the same amount.
        const std::string seed = str(provider().randomBytes(64));
        return ExtKey(provider().extKeyFromSeed(view(seed), ALG), true);
    });
}

ExtKey::ExtKey() {}

ExtKey::ExtKey(std::shared_ptr<privmx::cryptoservice::IExtKey> impl, bool isPrivate)
    : _impl(std::move(impl)), _isPrivate(isPrivate) {}

ExtKey ExtKey::derive(uint32_t index) const {
    return guarded([&] { return ExtKey(_impl->deriveChild(ALG, ALG, index, false), true); });
}

ExtKey ExtKey::deriveHardened(uint32_t index) const {
    return guarded([&] { return ExtKey(_impl->deriveChild(ALG, ALG, index, true), true); });
}

std::string ExtKey::getPrivatePartAsBase58() const {
    return guarded([&] {
        if (!_isPrivate) {
            throw core::Exception("ExtKey: no private part");
        }
        // Already base58-with-checksum; the format name is the encoding, not a request for bytes.
        return str(_impl->export_(cs::KeyFormat::Base58));
    });
}

std::string ExtKey::getPublicPartAsBase58() const {
    return guarded([&] {
        // Built as a separate public-only extended key, because an extended key exports whichever
        // halves it holds and a private one would export the private part. The result round-trips
        // through `fromBase58` and refuses every private operation, which is what callers use it
        // for; it carries no chain code, so it cannot itself be derived from.
        auto publicOnly = provider().extKeyFromPublicKey(_impl->publicKey(cs::KeyUsageScheme::Sign));
        return str(publicOnly->export_(cs::KeyFormat::Base58));
    });
}

std::string ExtKey::getPrivateKey() const {
    return guarded([&] {
        if (!_isPrivate) {
            throw core::Exception("ExtKey: no private part");
        }
        return str(_impl->privateKey(cs::KeyUsageScheme::Sign)->export_(cs::KeyFormat::Wif));
    });
}

std::string ExtKey::getPublicKey() const {
    return guarded([&] {
        return str(_impl->publicKey(cs::KeyUsageScheme::Sign)->export_(cs::KeyFormat::Base58Der));
    });
}

privmx::endpoint::core::Buffer ExtKey::getPrivateEncKey() const {
    return guarded([&] {
        if (!_isPrivate) {
            throw core::Exception("ExtKey: no private part");
        }
        // The key-agreement half, which for a composed identity is a different key from the signing
        // one — hence the usage scheme rather than a second accessor.
        return core::Buffer::from(
            str(_impl->privateKey(cs::KeyUsageScheme::DerEnc)->export_(cs::KeyFormat::Raw))
        );
    });
}

std::string ExtKey::getPublicKeyAsBase58Address() const {
    return guarded([&] {
        return str(_impl->publicKey(cs::KeyUsageScheme::Sign)->export_(cs::KeyFormat::Base58DerAddr));
    });
}

privmx::endpoint::core::Buffer ExtKey::getChainCode() const {
    return guarded([&] { return core::Buffer::from(str(_impl->chainCode())); });
}

bool ExtKey::verifyCompactSignatureWithHash(
    const privmx::endpoint::core::Buffer& message,
    const privmx::endpoint::core::Buffer& signature
) const {
    return guarded([&] {
        return _impl->publicKey(cs::KeyUsageScheme::Sign)
            ->verify(view(message.stdString()), view(signature.stdString()), cs::SigScheme::Compact);
    });
}

bool ExtKey::isPrivate() const {
    return _isPrivate;
}
