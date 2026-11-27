/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/cryptoservice/base/AsyncExceptions.hpp>
#include <privmx/cryptoservice/base/Exceptions.hpp>

#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoErrors.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

namespace {

std::string describe(const std::exception& e, const std::string& context) {
    return context + ": " + e.what();
}

} // namespace

void CryptoErrors::rethrow(const std::exception& e, const std::string& context) {
    const std::string description = describe(e, context);

    // Order matters: most specific first, going down pmx-crypto's hierarchy. Its exceptions carry
    // no code (every one has `code == 0`), so they are recognised by type, not by value.

    // --- cases the endpoint already has an exact counterpart for ------------------------------
    // The old codes are kept, so wrappers that react to a particular error keep working.

    // Failed authentication on decryption — a wrong key or tampered data. This is the only
    // decryption error with a security meaning, and the old endpoint had a code of its own for it,
    // so it is preserved. Mind the naming trap: an AEAD reports this case as
    // `DecryptionFinalizationFailed` (EVP_DecryptFinal_ex), whereas `DecryptionInvalidTag` means
    // only that the ciphertext is shorter than the tag itself — that is, a malformed frame.
    if (dynamic_cast<const cs::PrivmxCryptoserviceDecryptionFinalizationFailedException*>(&e) != nullptr ||
        dynamic_cast<const cs::PrivmxCryptoserviceDecryptionWrongMessageSecurityTagException*>(&e) != nullptr) {
        throw crypto::WrongMessageSecurityTagException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceDecryptionInvalidTagException*>(&e) != nullptr) {
        throw MalformedCryptoFrameException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceBase58InvalidChecksumException*>(&e) != nullptr) {
        throw crypto::InvalidChecksumException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceBase58InvalidNetworkException*>(&e) != nullptr) {
        throw crypto::InvalidNetworkException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceBase58InvalidCompressionFlagkException*>(&e) != nullptr) {
        throw crypto::InvalidCompressionFlagException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceBase58InvalidWIFPayloadLengthException*>(&e) != nullptr) {
        throw crypto::InvalidWIFPayloadLengthException(description);
    }

    // --- the rest: by category (cryptographic role) -------------------------------------------
    // There are six categories and they cover the whole of `Exceptions.hpp` and `AsyncExceptions.hpp`.
    //
    // No separate branch for ECC: pmx-crypto retired `PrivmxCryptoserviceEccException`, and errors
    // from curve operations now derive from `PrivmxCryptoserviceAsyncKeyException`, which the
    // branch below catches. `crypto::EccOperationFailureException` stays in the API — the legacy
    // `crypto/` module still throws it — but it no longer leaves this function.

    if (dynamic_cast<const cs::PrivmxCryptoserviceAsyncKeyException*>(&e) != nullptr) {
        throw crypto::AsymmetricKeyFailureException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceSymmetricCipherException*>(&e) != nullptr) {
        throw crypto::SymmetricCipherFailureException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceKdfException*>(&e) != nullptr) {
        throw crypto::KdfFailureException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceHmacException*>(&e) != nullptr) {
        throw crypto::HmacFailureException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceDigestException*>(&e) != nullptr) {
        throw crypto::DigestFailureException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceRandomException*>(&e) != nullptr) {
        throw crypto::RandomGeneratorFailureException(description);
    }

    // The root of pmx-crypto's own hierarchy, and anything deriving from `std::runtime_error` that it
    // throws from outside that hierarchy.
    //
    // `CryptoProvider::encrypt` used to land here: it threw a bare `std::runtime_error` (through an
    // alias named `PrivmxDriverCryptoException`, unrelated to this library's class of that name) when
    // the cipher failed to finalize. It now throws `PrivmxCryptoserviceEncryptionUpdateFailedException`
    // and `...EncryptionFinalizationFailedException`, both under `PrivmxCryptoserviceSymmetricCipherException`,
    // so those are caught by the branch above and reported as `SymmetricCipherFailureException` rather
    // than falling through to this one. The branch stays: it is the catch-all for a hierarchy that is
    // still growing, and a pmx-crypto error reaching the caller untranslated would carry no code.
    throw crypto::EndpointCryptoException(description);
}
