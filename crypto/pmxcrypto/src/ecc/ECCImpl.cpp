/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/pmxcrypto/ecc/ECCImpl.hpp>

#include <cstdint>
#include <string>

#include <privmx/cryptoservice/base/CoreTypes.hpp>
#include <privmx/cryptoservice/base/Exceptions.hpp>

#include <privmx/crypto/CryptoConfig.hpp>
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/pmxcrypto/ProviderAccess.hpp>

namespace cs = privmx::cryptoservice;

using namespace privmx;
using namespace privmx::crypto;
using namespace std;

namespace {

cs::BytesView view(const std::string& data) {
    return cs::BytesView(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

std::string str(const cs::Bytes& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

template<class Operation>
auto mapped(const char* what, Operation&& operation) -> decltype(operation()) {
    try {
        return operation();
    } catch (const cs::Exception& e) {
        throw CryptoException(std::string(what) + ": " + e.what());
    }
}

/**
 * The order of the secp256k1 group, as the 32 bytes `ECC::getOrder` has always returned.
 *
 * A published domain parameter, not a property of any particular key — the entry point it replaces
 * took no key argument either and handed back this same constant. pmx-crypto exposes no accessor
 * for it, and the only caller is BIP32 child derivation in `ExtKey`, where every reference
 * implementation carries the same literal.
 */
const unsigned char SECP256K1_ORDER[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

/**
 * The leading byte of a compact signature.
 *
 * Written as a constant, exactly as the driver did, rather than derived from a recovery id. It is
 * part of the format: `ECC::verify` range-checks it and then ignores it, so computing a real tag
 * here would still interoperate while changing the bytes on the wire. `EccVectorsTest` pins it.
 */
constexpr char COMPACT_SIGNATURE_HEADER = 27;
constexpr size_t COMPACT_SIGNATURE_LENGTH = 65;

/// Width of a secp256k1 private scalar.
constexpr size_t SCALAR_LENGTH = 32;

} // namespace

#ifdef PRIVMX_DEFAULT_CRYPTO_DRIVER
privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::genPair() {
    return privmx::crypto::pmximpl::ECCImpl::genPair();
}

privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::fromPublicKey(const string& public_key) {
    return privmx::crypto::pmximpl::ECCImpl::fromPublicKey(public_key);
}

privmx::crypto::ECCImpl::Ptr privmx::crypto::ECCImpl::fromPrivateKey(const string& private_key) {
    return privmx::crypto::pmximpl::ECCImpl::fromPrivateKey(private_key);
}
#endif

pmximpl::ECCImpl::ECCImpl(shared_ptr<cs::IPrivateKey> priv, shared_ptr<cs::IPublicKey> pub)
    : _priv(move(priv)), _pub(move(pub)) {}

pmximpl::ECCImpl::Ptr pmximpl::ECCImpl::genPair() {
    return mapped("eccGenPair", [&]() -> pmximpl::ECCImpl::Ptr {
        auto priv = cryptoProvider().generatePrivateKey(cs::AsymAlg::PrivmxSecp256k1);
        return new pmximpl::ECCImpl(priv, priv->publicKey());
    });
}

pmximpl::ECCImpl::Ptr pmximpl::ECCImpl::fromPrivateKey(const string& private_key) {
    // Left-padded to the full scalar width, because the driver accepted a short buffer and callers
    // rely on that: BIP32 derivation in `ExtKey` builds the child scalar with mpz_export, which
    // omits leading zeros, so a key whose top byte is zero arrives 31 bytes long. pmx-crypto wants
    // exactly 32. The two are the same integer — this is padding, not reinterpretation — and BIP32
    // test vectors 3 and 4 exist precisely to catch an implementation that gets it wrong.
    string scalar = private_key;
    if (scalar.size() < SCALAR_LENGTH) {
        scalar.insert(0, SCALAR_LENGTH - scalar.size(), '\0');
    }
    return mapped("eccFromPrivateKey", [&]() -> pmximpl::ECCImpl::Ptr {
        auto priv = cryptoProvider().importPrivateKey(view(scalar), cs::KeyFormat::Raw, cs::AsymAlg::PrivmxSecp256k1);
        return new pmximpl::ECCImpl(priv, priv->publicKey());
    });
}

pmximpl::ECCImpl::Ptr pmximpl::ECCImpl::fromPublicKey(const string& public_key) {
    return mapped("eccFromPublicKey", [&]() -> pmximpl::ECCImpl::Ptr {
        // `Der` here is the bare EC point, compressed or not, which is what the driver's
        // eccFromPublicKey accepted too.
        auto pub = cryptoProvider().importPublicKey(view(public_key), cs::KeyFormat::Der, cs::AsymAlg::PrivmxSecp256k1);
        return new pmximpl::ECCImpl(nullptr, pub);
    });
}

void pmximpl::ECCImpl::validate() const {
    if (isEmpty()) {
        throw ECCIsNotInitializedException();
    }
}

pmximpl::ECCImpl::operator bool() const {
    return !isEmpty();
}

bool pmximpl::ECCImpl::isEmpty() const {
    return _pub == nullptr;
}

bool pmximpl::ECCImpl::hasPrivate() const {
    return _priv != nullptr;
}

string pmximpl::ECCImpl::getPublicKey(bool compact) const {
    validate();
    return mapped("eccGetPublicKey", [&] {
        const string compressed = str(_pub->export_(cs::KeyFormat::Der));
        if (compact) {
            return compressed;
        }
        // PrivmxSecp256k1 always exports compressed - in pmx-crypto's terms the uncompressed form
        // is a separate algorithm on the same curve, so the point is re-read as plain `secp256k1`,
        // whose raw export is the 65-byte form. Only the compressed form is used in production;
        // this path serves key-import tests, which is why the extra import costs nothing that
        // matters.
        auto asPlainCurve =
            cryptoProvider().importPublicKey(view(compressed), cs::KeyFormat::Der, cs::AsymAlg::secp256k1);
        return str(asPlainCurve->export_(cs::KeyFormat::Raw));
    });
}

string pmximpl::ECCImpl::getPrivateKey() const {
    validate();
    if (!hasPrivate()) {
        // What the driver produced for a public-only key: an empty big number, which serialised to
        // nothing rather than raising.
        return string();
    }
    return mapped("eccGetPrivateKey", [&] {
        string scalar = str(_priv->export_(cs::KeyFormat::Raw));
        // Leading zeros are stripped, because the driver returned a *big number* here and that is
        // what callers were built against. It is load-bearing, not cosmetic:
        // `ExtKey::derive` chooses between `fillTo32(key)` and the bare `key` depending on whether
        // it is reproducing the old PrivMX derivation, and the old one hashes exactly these bytes.
        // Returning a padded scalar silently changes every child key derived that way — which is
        // what BIP32 test vectors 3 and 4 caught, both having a master key whose top byte is zero.
        const size_t firstSignificant = scalar.find_first_not_of('\0');
        if (firstSignificant == string::npos) {
            return string();
        }
        return scalar.substr(firstSignificant);
    });
}

string pmximpl::ECCImpl::sign(const string& data) const {
    validate();
    if (!hasPrivate()) {
        throw ECCIsNotInitializedException();
    }
    return mapped("eccSign", [&] {
        // `data` is the **message**, not a digest: for secp256k1 `Compact` is EVP_DigestSign with
        // SHA-256, so the provider hashes it here (`CompactWithHash` would hash a second time).
        // There is no scheme that signs a digest handed to it, which is why the callers above stopped
        // pre-hashing — `EccVectorsTest.SignsOverASingleSha256` pins which of the two this is.
        string signature = str(_priv->sign(view(data), cs::SigScheme::Compact));
        if (signature.size() != COMPACT_SIGNATURE_LENGTH) {
            throw InvalidSignatureSizeException(to_string(signature.size()));
        }
        signature[0] = COMPACT_SIGNATURE_HEADER;
        return signature;
    });
}

bool pmximpl::ECCImpl::verify(const string& data, const string& signature) const {
    validate();
    if (signature.size() != COMPACT_SIGNATURE_LENGTH) {
        throw InvalidSignatureSizeException();
    }
    if (signature.front() < 27 || signature.front() > 42) {
        throw InvalidSignatureHeaderException();
    }
    return mapped("eccVerify", [&] {
        return _pub->verify(view(data), view(signature), cs::SigScheme::Compact);
    });
}

string pmximpl::ECCImpl::derive(const privmx::crypto::ECCImpl::Ptr ecc) const {
    validate();
    if (!hasPrivate()) {
        throw ECCIsNotInitializedException();
    }
    auto other = ecc.cast<pmximpl::ECCImpl>();
    if (other.isNull() || other->publicKeyHandle() == nullptr) {
        throw ECCIsNotInitializedException();
    }
    return mapped("eccDerive", [&] { return str(_priv->deriveSharedSecret(other->publicKeyHandle())); });
}

string pmximpl::ECCImpl::getOrder() const {
    return string(reinterpret_cast<const char*>(SECP256K1_ORDER), sizeof(SECP256K1_ORDER));
}
