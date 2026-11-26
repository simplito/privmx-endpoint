/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/pmxcrypto/CryptoService.hpp>

#include <cstdint>
#include <string>
#include <tuple>

#include <privmx/cryptoservice/base/CoreTypes.hpp>
#include <privmx/cryptoservice/base/Exceptions.hpp>

#include <privmx/crypto/CipherType.hpp>
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

/**
 * Translates pmx-crypto's exceptions into the ones this API has always thrown.
 *
 * Callers of `privmx::crypto` catch `privmx::crypto::*`; letting pmx-crypto's own hierarchy escape
 * would change what every one of them sees. The tag failure is mapped by name because it is the one
 * the callers act on rather than merely report — `aes256CbcHmac256Decrypt` is reached from data a
 * peer supplied, so "the tag did not match" is a normal outcome, not an internal error.
 */
template<class Operation>
auto mapped(const char* what, Operation&& operation) -> decltype(operation()) {
    try {
        return operation();
    } catch (const cs::PrivmxCryptoserviceDecryptionWrongMessageSecurityTagException& e) {
        throw WrongMessageSecurityTagException(std::string(what) + ": " + e.what());
    } catch (const cs::PrivmxCryptoserviceDecryptionInvalidKeySizeException& e) {
        throw DecryptInvalidKeyLengthException(std::string(what) + ": " + e.what());
    } catch (const cs::PrivmxCryptoserviceDecryptionInvalidIvSizeException& e) {
        throw IncorrectParamsException(std::string(what) + ": " + e.what());
    } catch (const cs::Exception& e) {
        throw CryptoException(std::string(what) + ": " + e.what());
    }
}

std::string symmetric(
    const char* what,
    cs::SymAlg cipher,
    const std::string& data,
    const std::string& key,
    const std::string& iv,
    bool encrypting,
    const std::string& aad = std::string()
) {
    return mapped(what, [&] {
        const cs::SymParams params{.cipher = cipher, .key = view(key), .iv = view(iv), .aad = view(aad), .taglen = 0};
        return str(
            encrypting ? pmximpl::cryptoProvider().encrypt(params, view(data)) :
                         pmximpl::cryptoProvider().decrypt(params, view(data))
        );
    });
}

} // namespace

// ---------------------------------------------------------------------------------------------
// The sixteen primitives the provider supplies whole.
// ---------------------------------------------------------------------------------------------

string pmximpl::CryptoService::randomBytes(size_t length) const {
    return mapped("randomBytes", [&] { return str(cryptoProvider().randomBytes(length)); });
}

string pmximpl::CryptoService::hmacSha256(const string& key, const string& data) const {
    return mapped("hmacSha256", [&] { return str(cryptoProvider().hmac(cs::Hash::Sha256, view(key), view(data))); });
}

string pmximpl::CryptoService::sha256(const string& data) const {
    return mapped("sha256", [&] { return str(cryptoProvider().digest(cs::Hash::Sha256, view(data))); });
}

string pmximpl::CryptoService::aes256CbcNoPadEncrypt(const string& data, const string& key, const string& iv) const {
    return symmetric("aes256CbcNoPadEncrypt", cs::SymAlg::Aes256CbcNoPad, data, key, iv, true);
}

string pmximpl::CryptoService::aes256CbcNoPadDecrypt(const string& data, const string& key, const string& iv) const {
    return symmetric("aes256CbcNoPadDecrypt", cs::SymAlg::Aes256CbcNoPad, data, key, iv, false);
}

string pmximpl::CryptoService::aes256CbcPkcs7Encrypt(const string& data, const string& key, const string& iv) const {
    return symmetric("aes256CbcPkcs7Encrypt", cs::SymAlg::Aes256Cbc, data, key, iv, true);
}

string pmximpl::CryptoService::aes256CbcPkcs7Decrypt(const string& data, const string& key, const string& iv) const {
    return symmetric("aes256CbcPkcs7Decrypt", cs::SymAlg::Aes256Cbc, data, key, iv, false);
}

std::string pmximpl::CryptoService::pbkdf2(
    const std::string& password,
    const std::string& salt,
    const int32_t rounds,
    const size_t length,
    const std::string& hash
) const {
    // The hash arrives as the string the driver's C API took. Only the three this library ever asks
    // for are accepted; anything else was an error there too, just a less specific one.
    cs::Hash alg;
    if (hash == "SHA256") {
        alg = cs::Hash::Sha256;
    } else if (hash == "SHA512") {
        alg = cs::Hash::Sha512;
    } else if (hash == "SHA1") {
        alg = cs::Hash::Sha1;
    } else {
        throw UnsupportedHashAlgorithmException("pbkdf2: " + hash);
    }
    return mapped("pbkdf2", [&] {
        const cs::KdfParams params{
            .kdf = cs::Kdf::Pbkdf2, .length = length, .hash = alg, .rounds = rounds, .salt = view(salt)
        };
        return str(cryptoProvider().derive(params, view(password)));
    });
}

// ---------------------------------------------------------------------------------------------
// Composed constructions.
//
// These are built from HMAC and CBC rather than handed over whole, and every one of them is a wire
// format the bridge implements too. They are **delegated** to pmx-crypto rather than reimplemented:
// composing AEAD out of parts is the classic way to introduce a subtle, silent break, and doing it
// in two places at once doubles the chance that only one of them gets fixed.
//
// What makes the delegation safe is not that pmx-crypto's code reads the same, but
// `CompositionVectorsTest`: golden vectors computed from an independent model of each construction,
// which passed against the previous hand-written implementation and pass against this one.
//
// `ctDecrypt` below stays local - it is byte layout (a one-byte cipher-type prefix), not a
// cryptographic construction, and pmx-crypto has no equivalent to delegate to.
// ---------------------------------------------------------------------------------------------

string pmximpl::CryptoService::prf_tls12(const string& key, const string& seed, size_t length) const {
    return mapped("prf_tls12", [&] {
        // The seed travels as `salt`; pmx-crypto's Prf12 takes the key as the secret data.
        const cs::KdfParams params{
            .kdf = cs::Kdf::Prf12, .length = length, .hash = cs::Hash::Sha256, .rounds = 0, .salt = view(seed)
        };
        return str(cryptoProvider().derive(params, view(key)));
    });
}

string pmximpl::CryptoService::aes256CbcHmac256Decrypt(string data, const string& key32, size_t taglen) const {
    // The tag check lives inside pmx-crypto now. Its failure arrives as
    // PrivmxCryptoserviceDecryptionWrongMessageSecurityTagException and `mapped` turns that back
    // into WrongMessageSecurityTagException, which is what callers here have always caught.
    return mapped("aes256CbcHmac256Decrypt", [&] {
        const cs::SymParams params{
            .cipher = cs::SymAlg::Aes256CbcHmac, .key = view(key32), .iv = {}, .aad = {}, .taglen = taglen
        };
        return str(cryptoProvider().decrypt(params, view(data)));
    });
}

string pmximpl::CryptoService::ctDecrypt(
    const string& data,
    const string& key32,
    const string& iv16,
    size_t taglen,
    [[maybe_unused]] const string& key16
) const {
    if (key32.length() != 32) {
        throw DecryptInvalidKeyLengthException("required: 32, received: " + to_string(key32.length()));
    }
    switch (data[0]) {
        case CipherType::AES_256_CBC_PKCS7_NO_IV:
            if (iv16.empty()) {
                throw MissingIvException();
            }
            return aes256CbcPkcs7Decrypt(data.substr(1), key32, iv16);
        case CipherType::AES_256_CBC_PKCS7_WITH_IV:
            return aes256CbcPkcs7Decrypt(data.substr(17), key32, data.substr(1, 16));
        case CipherType::XTEA_ECB_PKCS7:
            throw NotImplementedException();
        case CipherType::AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256:
            return aes256CbcHmac256Decrypt(data.substr(1), key32, taglen);
    }
    throw UnknownDecryptionTypeException(to_string(data[0]));
}
