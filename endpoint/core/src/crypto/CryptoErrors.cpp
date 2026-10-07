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

    // Kolejnosc ma znaczenie: od najbardziej szczegolowych w dol hierarchii pmx-crypto.
    // Wyjatki pmx-crypto nie niosa kodu (wszystkie maja `code == 0`), wiec rozpoznajemy
    // je po typie, a nie po wartosci.

    // --- przypadki, dla ktorych endpoint ma juz dokladny odpowiednik -------------------------
    // Zachowujemy stare kody, zeby wrappery reagujace na konkretny blad dalej dzialaly.

    // Nieudane uwierzytelnienie przy deszyfrowaniu - zly klucz albo naruszone dane.
    // To jedyny blad deszyfrowania o znaczeniu bezpieczenstwa i stary endpoint mial na niego
    // osobny kod, wiec go zachowujemy. Uwaga na pulapke nazw: AEAD zglasza ten przypadek jako
    // `DecryptionFinalizationFailed` (EVP_DecryptFinal_ex), natomiast `DecryptionInvalidTag`
    // znaczy tylko tyle, ze szyfrogram jest krotszy niz sam tag - czyli ramka jest uszkodzona.
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

    // --- pozostale: po kategorii (roli kryptograficznej) --------------------------------------
    // Kategorii jest siedem i pokrywaja cale `Exceptions.hpp` oraz `AsyncExceptions.hpp`.

    if (dynamic_cast<const cs::PrivmxCryptoserviceAsyncKeyException*>(&e) != nullptr) {
        throw crypto::AsymmetricKeyFailureException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceSymmetricCipherException*>(&e) != nullptr) {
        throw crypto::SymmetricCipherFailureException(description);
    }
    if (dynamic_cast<const cs::PrivmxCryptoserviceEccException*>(&e) != nullptr) {
        throw crypto::EccOperationFailureException(description);
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

    // Korzen hierarchii pmx-crypto oraz goly `std::runtime_error`, ktory pmx-crypto rzuca
    // z `CryptoProvider::encrypt` (`PrivmxDriverCryptoException` to alias na `std::runtime_error`).
    throw crypto::EndpointCryptoException(description);
}
