/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/cryptoservice/base/CoreTypes.hpp>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoErrors.hpp>
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>
#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

PublicKey PublicKey::fromBase58DER(const std::string& base58DER) {
    return mapCryptoErrors("PublicKey::fromBase58DER", [&] {
        // The Base58DER form does not name its algorithm today — agreeing on a shared, tagged
        // encoding is pending on the bridge (crypto-update/issue-bridge-remaining.md §2). Until
        // then the import assumes the default algorithm but **records** it on the key, so once the
        // encoding starts carrying it, only this spot changes, not the operations using the key.
        return PublicKey(
            cryptoProvider().importPublicKey(keyBytes(base58DER), cs::KeyFormat::Base58Der, DEFAULT_KEY_ALGORITHM),
            DEFAULT_KEY_ALGORITHM
        );
    });
}

PublicKey PublicKey::fromDER(const std::string& der) {
    // Two lengths, because the old implementation accepted both and external data (e.g. a key
    // extracted from a PGP block) arrives uncompressed.
    //
    //   33 B — compressed form, PrivMX's data format
    //   65 B — uncompressed form; `PrivmxSecp256k1` does not accept it, so the import goes through
    //          plain `secp256k1` + `Raw`. The export returns the compressed form either way, so the
    //          caller sees no difference.
    constexpr std::size_t COMPRESSED_LENGTH = 33;
    constexpr std::size_t UNCOMPRESSED_LENGTH = 65;
    return mapCryptoErrors("PublicKey::fromDER", [&] {
        if (der.size() == UNCOMPRESSED_LENGTH) {
            // A different algorithm as `pmx-crypto` sees it (same curve, different data format), so
            // the key records that one — operations on it must follow the format it was read in.
            return PublicKey(
                cryptoProvider().importPublicKey(keyBytes(der), cs::KeyFormat::Raw, cs::AsymAlg::secp256k1),
                cs::AsymAlg::secp256k1
            );
        }
        if (der.size() != COMPRESSED_LENGTH) {
            throw MalformedEncryptionKeyException(
                "public key DER of unexpected length: " + std::to_string(der.size())
            );
        }
        return PublicKey(
            cryptoProvider().importPublicKey(keyBytes(der), cs::KeyFormat::Der, DEFAULT_KEY_ALGORITHM),
            DEFAULT_KEY_ALGORITHM
        );
    });
}

const cs::IPublicKey& PublicKey::require() const {
    if (_key == nullptr) {
        throw MalformedEncryptionKeyException("operation on an empty public key");
    }
    return *_key;
}

bool PublicKey::operator==(const PublicKey& other) const {
    if (empty() || other.empty()) {
        return empty() && other.empty();
    }
    return toBase58DER() == other.toBase58DER();
}

std::string PublicKey::toDER() const {
    return mapCryptoErrors("PublicKey::toDER", [&] { return keyString(require().export_(cs::KeyFormat::Der)); });
}

std::string PublicKey::toBase58DER() const {
    return mapCryptoErrors("PublicKey::toBase58DER", [&] {
        return keyString(require().export_(cs::KeyFormat::Base58Der));
    });
}

bool PublicKey::verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const {
    return mapCryptoErrors("PublicKey::verifyCompactSignatureWithHash", [&] {
        // The scheme comes from **this** key's algorithm, not from a constant: a user's key may be
        // of any algorithm, and verifying with the wrong scheme would reject valid signatures.
        return require().verify(keyBytes(message), keyBytes(signature), signatureSchemeFor(_algorithm));
    });
}
