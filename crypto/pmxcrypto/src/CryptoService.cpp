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

#include <Poco/ByteOrder.h>

#include <privmx/cryptoservice/base/CoreTypes.hpp>
#include <privmx/cryptoservice/base/Exceptions.hpp>

#include <privmx/crypto/CipherType.hpp>
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/pmxcrypto/ProviderAccess.hpp>

namespace cs = privmx::cryptoservice;

using namespace privmx;
using namespace privmx::crypto;
using namespace std;
using Poco::ByteOrder;
using Poco::UInt32;

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
// The sixteen that used to call privmxdrvcrypto.
// ---------------------------------------------------------------------------------------------

string pmximpl::CryptoService::randomBytes(size_t length) const {
    return mapped("randomBytes", [&] { return str(cryptoProvider().randomBytes(length)); });
}

string pmximpl::CryptoService::hmacSha1(const string& key, const string& data) const {
    return mapped("hmacSha1", [&] { return str(cryptoProvider().hmac(cs::Hash::Sha1, view(key), view(data))); });
}

string pmximpl::CryptoService::hmacSha256(const string& key, const string& data) const {
    return mapped("hmacSha256", [&] { return str(cryptoProvider().hmac(cs::Hash::Sha256, view(key), view(data))); });
}

string pmximpl::CryptoService::hmacSha512(const string& key, const string& data) const {
    return mapped("hmacSha512", [&] { return str(cryptoProvider().hmac(cs::Hash::Sha512, view(key), view(data))); });
}

string pmximpl::CryptoService::sha1(const string& data) const {
    return mapped("sha1", [&] { return str(cryptoProvider().digest(cs::Hash::Sha1, view(data))); });
}

string pmximpl::CryptoService::sha256(const string& data) const {
    return mapped("sha256", [&] { return str(cryptoProvider().digest(cs::Hash::Sha256, view(data))); });
}

string pmximpl::CryptoService::sha512(const string& data) const {
    return mapped("sha512", [&] { return str(cryptoProvider().digest(cs::Hash::Sha512, view(data))); });
}

string pmximpl::CryptoService::ripemd160(const string& data) const {
    return mapped("ripemd160", [&] { return str(cryptoProvider().digest(cs::Hash::Ripemd160, view(data))); });
}

string pmximpl::CryptoService::aes256EcbEncrypt(const string& data, const string& key) const {
    // ECB takes no IV; pmx-crypto reads none for this algorithm.
    return symmetric("aes256EcbEncrypt", cs::SymAlg::Aes256Ecb, data, key, std::string(), true);
}

string pmximpl::CryptoService::aes256EcbDecrypt(const string& data, const string& key) const {
    return symmetric("aes256EcbDecrypt", cs::SymAlg::Aes256Ecb, data, key, std::string(), false);
}

string pmximpl::CryptoService::aes256CbcPkcs7Encrypt(const string& data, const string& key, const string& iv) const {
    return symmetric("aes256CbcPkcs7Encrypt", cs::SymAlg::Aes256Cbc, data, key, iv, true);
}

string pmximpl::CryptoService::aes256CbcPkcs7Decrypt(const string& data, const string& key, const string& iv) const {
    return symmetric("aes256CbcPkcs7Decrypt", cs::SymAlg::Aes256Cbc, data, key, iv, false);
}

string pmximpl::CryptoService::aes256CbcNoPadEncrypt(const string& data, const string& key, const string& iv) const {
    return symmetric("aes256CbcNoPadEncrypt", cs::SymAlg::Aes256CbcNoPad, data, key, iv, true);
}

string pmximpl::CryptoService::aes256CbcNoPadDecrypt(const string& data, const string& key, const string& iv) const {
    return symmetric("aes256CbcNoPadDecrypt", cs::SymAlg::Aes256CbcNoPad, data, key, iv, false);
}

string pmximpl::CryptoService::aes256GcmEncrypt(
    const string& data,
    const string& key,
    const string& iv,
    const string& aad
) const {
    // The driver returned ciphertext followed by the tag, assembled by hand; pmx-crypto appends the
    // tag itself, so the result is the same bytes.
    return mapped("aes256GcmEncrypt", [&] {
        const cs::SymParams params{
            .cipher = cs::SymAlg::Aes256Gcm, .key = view(key), .iv = view(iv), .aad = view(aad), .taglen = 16
        };
        return str(cryptoProvider().encrypt(params, view(data)));
    });
}

string pmximpl::CryptoService::aes256GcmDecrypt(
    const string& data,
    const string& key,
    const string& iv,
    const string& aad
) const {
    // The driver split the trailing tag off before calling down, and rejected anything shorter than
    // one. pmx-crypto takes the tag as part of the input, so only the length check is kept — without
    // it a short buffer would be reported as a tag mismatch rather than as a malformed frame.
    if (data.size() < 16) {
        throw CryptoException("aes256GcmDecrypt: no tag");
    }
    return mapped("aes256GcmDecrypt", [&] {
        const cs::SymParams params{
            .cipher = cs::SymAlg::Aes256Gcm, .key = view(key), .iv = view(iv), .aad = view(aad), .taglen = 16
        };
        return str(cryptoProvider().decrypt(params, view(data)));
    });
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
// The twelve built on top of the above. Carried over from the driver implementation unchanged:
// they are backend-independent, and each one is a wire format shared with the bridge, so the only
// safe edit here is no edit.
// ---------------------------------------------------------------------------------------------

string pmximpl::CryptoService::hash160(const string& data) const {
    string data_sha256 = sha256(data);
    return ripemd160(data_sha256);
}

string pmximpl::CryptoService::prf_tls12(const string& key, const string& seed, size_t length) const {
    string a = seed;
    string result = "";
    while (result.length() < length) {
        a = hmacSha256(key, a);
        string tmp = a + seed;
        string d = hmacSha256(key, tmp);
        result.append(d);
    }
    return result.substr(0, length);
}

string pmximpl::CryptoService::kdf(size_t length, const string& key, const string& label) const {
    UInt32 len = ByteOrder::toBigEndian((UInt32)length);
    string seed = label + '\0' + string((char*)&len, 4);
    string k = "";
    UInt32 i = 1;
    string result;
    while (result.length() < length) {
        string input = k;
        UInt32 count = ByteOrder::toBigEndian(i++);
        input.append((char*)&count, 4).append(seed);
        k = hmacSha256(key, input);
        result.append(k);
    }
    return result.substr(0, length);
}

string pmximpl::CryptoService::generateIv(const string& key, Poco::Int32 idx) const {
    return hmacSha256(key, "iv" + to_string(idx)).substr(0, 16);
}

tuple<string, string> pmximpl::CryptoService::getKEM(const string& key, size_t kelen, size_t kmlen) const {
    string kEM = kdf(kelen + kmlen, key, "key expansion");
    return make_tuple(kEM.substr(0, kelen), kEM.substr(kelen));
}

string pmximpl::CryptoService::aes256CbcHmac256Encrypt(string data, const string& key32, string iv, size_t taglen)
    const {
    string kE, kM;
    tie(kE, kM) = getKEM(key32);
    if (iv.empty()) {
        iv = hmacSha256(key32, data);
    }
    iv = iv.substr(0, 16);
    data = string(16, 0).append(data);
    string cipher = aes256CbcPkcs7Encrypt(data, kE, iv);
    string tag = hmacSha256(kM, cipher).substr(0, taglen);
    return cipher.append(tag);
}

string pmximpl::CryptoService::aes256CbcHmac256Decrypt(string data, const string& key32, size_t taglen) const {
    string kE, kM;
    tie(kE, kM) = getKEM(key32);
    string tag = data.substr(data.length() - taglen);
    data = data.substr(0, data.length() - taglen);
    string rtag = hmacSha256(kM, data).substr(0, taglen);
    if (tag != rtag) {
        throw WrongMessageSecurityTagException();
    }
    string iv = data.substr(0, 16);
    data = data.substr(16);
    return aes256CbcPkcs7Decrypt(data, kE, iv);
}

string pmximpl::CryptoService::ctAes256CbcPkcs7NoIv(const string& data, const string& key, const string& iv) const {
    return CipherType::AES_256_CBC_PKCS7_NO_IV + aes256CbcPkcs7Encrypt(data, key, iv);
}

string pmximpl::CryptoService::ctAes256CbcPkcs7WithIv(const string& data, const string& key, const string& iv) const {
    return CipherType::AES_256_CBC_PKCS7_WITH_IV + iv + aes256CbcPkcs7Encrypt(data, key, iv);
}

string pmximpl::CryptoService::ctAes256CbcPkcs7WithIvAndHmacSha256(
    const string& data,
    const string& key,
    const string& iv,
    size_t taglen
) const {
    return CipherType::AES_256_CBC_PKCS7_WITH_IV_AND_HMAC_SHA256 + aes256CbcHmac256Encrypt(data, key, iv, taglen);
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
