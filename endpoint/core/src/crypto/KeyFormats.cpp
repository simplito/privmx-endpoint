/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <array>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

namespace {

struct KeyAlgorithmSpec {
    cs::AsymAlg algorithm;
    cs::SigScheme signatureScheme;
};

/**
 * Algorytmy kluczy tozsamosci, ktorych endpoint uzywa.
 *
 * Klucze uzytkownikow moga byc dowolnego algorytmu, wiec to jest rejestr **obslugi**, a nie
 * wyboru: wpis tutaj znaczy "umiemy takim kluczem podpisac i zweryfikowac". Dodanie Ed25519
 * bedzie dopisaniem wiersza.
 *
 * `PrivmxSecp256k1` i `secp256k1` to ta sama krzywa w dwoch formatach danych - oba podpisuja
 * tak samo. Drugi wystepuje tylko przy imporcie klucza publicznego w postaci nieskompresowanej.
 */
constexpr std::array<KeyAlgorithmSpec, 2> KEY_ALGORITHMS{{
    {cs::AsymAlg::PrivmxSecp256k1, cs::SigScheme::Compact},
    {cs::AsymAlg::secp256k1, cs::SigScheme::Compact},
}};

const KeyAlgorithmSpec* findSpec(cs::AsymAlg algorithm) {
    for (const auto& spec : KEY_ALGORITHMS) {
        if (spec.algorithm == algorithm) {
            return &spec;
        }
    }
    return nullptr;
}

constexpr bool defaultAlgorithmIsSupported() {
    for (const auto& spec : KEY_ALGORITHMS) {
        if (spec.algorithm == DEFAULT_KEY_ALGORITHM) {
            return true;
        }
    }
    return false;
}
static_assert(defaultAlgorithmIsSupported(), "DEFAULT_KEY_ALGORITHM nie ma wpisu w KEY_ALGORITHMS");

} // namespace

namespace privmx {
namespace endpoint {
namespace core {

bool isSupportedKeyAlgorithm(cs::AsymAlg algorithm) {
    return findSpec(algorithm) != nullptr;
}

cs::SigScheme signatureSchemeFor(cs::AsymAlg algorithm) {
    const KeyAlgorithmSpec* spec = findSpec(algorithm);
    if (spec == nullptr) {
        throw UnsupportedKeyAlgorithmException("asymmetric algorithm: " + std::to_string(static_cast<int>(algorithm)));
    }
    return spec->signatureScheme;
}

} // namespace core
} // namespace endpoint
} // namespace privmx
