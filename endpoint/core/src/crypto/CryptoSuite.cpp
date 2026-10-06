/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <array>
#include <mutex>

#include <privmx/cryptoservice/base/CoreTypes.hpp>
#include <privmx/cryptoservice/base/CryptoProviderRegistry.hpp>
#include <privmx/cryptoservice/provider/CryptoProvider.hpp>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoSuite.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

namespace {

/// Parametry jednego zestawu algorytmow.
struct SuiteSpec {
    SuiteId id;
    cs::SymAlg sym;
    cs::Hash hash;
    cs::Kdf kdf;
    std::size_t ivLength;
    /// Nazwa uzywana w `ContainerPolicy::cryptoSuite`. Limit wartosci polityki to 32 znaki.
    const char* policyName;
};

/**
 * Rejestr zestawow.
 *
 * Kompletny w kazdym buildzie - patrz CryptoSuite::known().
 * Oba wpisy sa trybami AEAD, bo tylko one pozwalaja uwierzytelnic znacznik zestawu
 * przez AAD. Tryb AES-256-CBC + HMAC tego nie potrafi (brak AAD w API providera),
 * wiec znacznik lezalby poza zakresem MAC - dokladnie ta wada, ktora ma dzis
 * bajt CipherType w starym formacie.
 */
constexpr std::array<SuiteSpec, 2> SUITES{{
    {SuiteId::Aes256GcmSha256, cs::SymAlg::Aes256Gcm, cs::Hash::Sha256, cs::Kdf::Kdf, 12, "aes256gcm-sha256"},
    {SuiteId::Aes256GcmSha512, cs::SymAlg::Aes256Gcm, cs::Hash::Sha512, cs::Kdf::Kdf, 12, "aes256gcm-sha512"},
}};

/// Zestaw uzywany do zapisu, gdy nic nie wskazuje innego (poziom 1 wyboru formatu).
constexpr SuiteId DEFAULT_WRITE_SUITE = SuiteId::Aes256GcmSha256;

/// Dlugosc tagu AEAD doklejanego przez providera do szyfrogramu.
constexpr std::size_t AEAD_TAG_LENGTH = 16;

const SuiteSpec* findSpec(SuiteId id) {
    for (const auto& spec : SUITES) {
        if (spec.id == id) {
            return &spec;
        }
    }
    return nullptr;
}

const SuiteSpec& requireSpec(SuiteId id) {
    const SuiteSpec* spec = findSpec(id);
    if (spec == nullptr) {
        throw UnknownCryptoSuiteException("suite id: " + std::to_string(static_cast<unsigned>(id)));
    }
    return *spec;
}

/**
 * Dostep do providera kryptograficznego.
 *
 * CryptoProviderRegistry::get() dereferencuje wskaznik bez sprawdzenia, wiec brak
 * rejestracji oznaczalby UB. Rejestrujemy leniwie i jednokrotnie - rejestr nie ma
 * wlasnej synchronizacji, a endpoint pracuje na puli watkow.
 */
cs::ICryptoProvider& provider() {
    static std::once_flag once;
    std::call_once(once, [] {
        if (!cs::CryptoProviderRegistry::getptr()) {
            cs::CryptoProviderRegistry::set(std::make_shared<cs::CryptoProvider>());
        }
    });
    return cs::CryptoProviderRegistry::get();
}

cs::BytesView view(const std::string& data) {
    return cs::BytesView(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

std::string str(const cs::Bytes& data) {
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

} // namespace

CryptoSuite CryptoSuite::defaultForWrite() {
    return CryptoSuite(DEFAULT_WRITE_SUITE);
}

CryptoSuite CryptoSuite::forId(SuiteId id) {
    requireSpec(id);
    return CryptoSuite(id);
}

bool CryptoSuite::isKnown(SuiteId id) {
    return findSpec(id) != nullptr;
}

CryptoSuite CryptoSuite::forPolicyValue(const std::string& value) {
    for (const auto& spec : SUITES) {
        if (value == spec.policyName) {
            return CryptoSuite(spec.id);
        }
    }
    throw UnknownCryptoSuiteException("policy value: '" + value + "'");
}

bool CryptoSuite::isKnownPolicyValue(const std::string& value) {
    for (const auto& spec : SUITES) {
        if (value == spec.policyName) {
            return true;
        }
    }
    return false;
}

std::string CryptoSuite::policyValue() const {
    return requireSpec(_id).policyName;
}

std::vector<SuiteId> CryptoSuite::known() {
    std::vector<SuiteId> result;
    result.reserve(SUITES.size());
    for (const auto& spec : SUITES) {
        result.push_back(spec.id);
    }
    return result;
}

std::string CryptoSuite::randomBytes(std::size_t length) const {
    return str(provider().randomBytes(length));
}

std::string CryptoSuite::hash(const std::string& data) const {
    return str(provider().digest(requireSpec(_id).hash, view(data)));
}

std::string CryptoSuite::mac(const std::string& key, const std::string& data) const {
    return str(provider().hmac(requireSpec(_id).hash, view(key), view(data)));
}

std::string CryptoSuite::deriveKey(const std::string& secret, const std::string& label, std::size_t length) const {
    const SuiteSpec& spec = requireSpec(_id);
    cs::KdfParams params{.kdf = spec.kdf, .length = length, .hash = spec.hash, .rounds = 0, .salt = {}, .label = label};
    return str(provider().derive(params, view(secret)));
}

std::string CryptoSuite::encrypt(const std::string& key, const std::string& plaintext) const {
    const SuiteSpec& spec = requireSpec(_id);
    const std::string iv = randomBytes(spec.ivLength);
    // Znacznik zestawu jest jednoczesnie pierwszym bajtem ramki i AAD, wiec jego podmiana
    // uniewaznia tag AEAD.
    const std::string tag(1, static_cast<char>(spec.id));
    cs::SymParams params{
        .cipher = spec.sym, .key = view(key), .iv = view(iv), .aad = view(tag), .taglen = AEAD_TAG_LENGTH
    };
    return tag + iv + str(provider().encrypt(params, view(plaintext)));
}

SuiteId CryptoSuite::readSuiteId(const std::string& framed) {
    if (framed.empty()) {
        throw MalformedCryptoFrameException("empty frame");
    }
    return static_cast<SuiteId>(static_cast<std::uint8_t>(framed[0]));
}

std::string CryptoSuite::decrypt(const std::string& key, const std::string& framed) {
    const SuiteSpec& spec = requireSpec(readSuiteId(framed));
    const std::size_t headerLength = 1 + spec.ivLength;
    if (framed.size() <= headerLength + AEAD_TAG_LENGTH) {
        throw MalformedCryptoFrameException("frame shorter than its header, iv and tag");
    }
    const std::string tag = framed.substr(0, 1);
    const std::string iv = framed.substr(1, spec.ivLength);
    const std::string ciphertext = framed.substr(headerLength);
    cs::SymParams params{
        .cipher = spec.sym, .key = view(key), .iv = view(iv), .aad = view(tag), .taglen = AEAD_TAG_LENGTH
    };
    return str(provider().decrypt(params, view(ciphertext)));
}
