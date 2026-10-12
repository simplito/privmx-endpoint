/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_CRYPTOEXCEPTION_HPP_
#define _PRIVMXLIB_CRYPTO_CRYPTOEXCEPTION_HPP_

#include <privmx/utils/PrivmxExtExceptions.hpp>
// must come last: the header above undefines the declaration macros when it is done with them
#include <privmx/endpoint/core/ExceptionMacros.hpp>

namespace privmx {
namespace crypto {
// clang-format off

DECLARE_SCOPE_ENDPOINT_EXCEPTION(CryptoException, "Unknown Crypto exception", "Crypto", 0xE0A1)

#define CRYPTO_EXCEPTIONS(X)                                                                                          \
    X(UnsupportedKeyFormatException, "Unsupported key format", 0x0001)                                                \
    X(EmptyPointException, "Empty point", 0x0002)                                                                     \
    X(InvalidSignatureSizeException, "Invalid signature size", 0x0003)                                                \
    X(InvalidSignatureHeaderException, "Invalid signature header", 0x0004)                                            \
    X(ECCIsNotInitializedException, "ECC is not initialized", 0x0005)                                                 \
    X(EmptyBNException, "Empty BN", 0x0006)                                                                           \
    X(WrongMessageSecurityTagException, "Wrong message security tag", 0x0007)                                         \
    X(DecryptInvalidKeyLengthException, "Decrypt invalid key length", 0x0008)                                         \
    X(MissingIvException, "Missing iv", 0x0009)                                                                       \
    X(UnknownDecryptionTypeException, "Unknown decryption type", 0x000A)                                              \
    X(UnsupportedHashAlgorithmException, "Unsupported hash algorithm", 0x000B)                                        \
    X(CryptoNotImplementedException, "Not implemented", 0x000C)                                                       \
    X(InvalidStrengthException, "Invalid strength", 0x000D)                                                           \
    X(InvalidEntropyException, "Invalid entropy", 0x000E)                                                             \
    X(InvalidMnemonicException, "Invalid mnemonic", 0x000F)                                                           \
    X(InvalidChecksumException, "Invalid checksum", 0x0010)                                                           \
    X(EncryptInvalidKeyLengthException, "Encrypt invalid key length", 0x0011)                                         \
    X(OnlyHmacSHA256WithIvIsSupportedForAES256CBCException, "Only hmac SHA-256 with iv is supported for AES-256-CBC", 0x0012) \
    X(CannotPassIvToDeterministicAES256CBCHmacSHA256Exception, "Cannot pass iv to deterministic AES-256-CBC hmac SHA-256", 0x0013) \
    X(XTEAECBEncryptionDoesntSupportHmacAndIvException, "XTEA-ECB encryption doesn't support hmac and iv", 0x0014)    \
    X(UnsupportedEncryptionAlgorithmException, "Unsupported encryption algorithm", 0x0015)                            \
    X(MissingRequiredSignatureException, "Missing required signature", 0x0016)                                        \
    X(InvalidFirstByteOfCipherException, "Invalid first byte of cipher", 0x0017)                                      \
    X(GivenPrivKeyDoesNotMatchException, "Given priv key does not match", 0x0018)                                     \
    X(UnsupportedAlgorithmException, "Unsupported algorithm", 0x0019)                                                 \
    X(UnsupportedVersionException, "Unsupported version", 0x001A)                                                     \
    X(IncorrectParamsException, "Incorrect params", 0x001B)                                                           \
    X(InvalidHandshakeStateException, "Invalid handshake state", 0x001C)                                              \
    X(InvalidBNException, "Invalid B N", 0x001D)                                                                      \
    X(InvalidM2Exception, "Invalid M2", 0x001E)                                                                       \
    X(InvalidVersionException, "Invalid version", 0x001F)                                                             \
    X(InvalidParentFingerprintException, "Invalid parent fingerprint", 0x0020)                                        \
    X(InvalidResultSizeException, "Invalid result size", 0x0022)                                                      \
    X(InvalidNetworkException, "Invalid network", 0x0023)                                                             \
    X(InvalidCompressionFlagException, "Invalid compression flag", 0x0024)                                            \
    X(InvalidWIFPayloadLengthException, "Invalid WIF payload length", 0x0025)                                         \
    X(OpenSSLException, "OpenSSL Exception", 0x0026)                                                                  \
    X(PrivmxDriverCryptoException, "privmxDrvCrypto Exception", 0x0027)                                               \
    X(PrivmxDriverEccException, "privmxDrvEcc Exception", 0x0028)                                                     \
    X(GivenPublicKeyDoesNotMatchWithSignatureException, "Given public key does not match with signature", 0x0029)     \
    X(ExtKeyDoesNotHoldPrivateKeyException, "Ext key does not hold private key", 0x002A)                              \
    X(InvalidExtendedKeySizeException, "BIP32 extended key must be exactly 78 bytes", 0x002B)

#define PRIVMX_CRYPTO_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(CryptoException, NAME, MSG, CODE)
CRYPTO_EXCEPTIONS(PRIVMX_CRYPTO_DECLARE)
#undef PRIVMX_CRYPTO_DECLARE

// old spelling, kept so the existing throw sites still compile
using NotImplementedException = CryptoNotImplementedException;

// compile-time guard: codes are collected from the list above, never retyped
#define PRIVMX_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(::privmx::endpoint::core::exceptionCodesUnique({
    CRYPTO_EXCEPTIONS(PRIVMX_CODE)
}), "Duplicate exception code in crypto scope");
#undef PRIVMX_CODE
#undef CRYPTO_EXCEPTIONS
// clang-format on
} // crypto
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_CRYPTO_CRYPTOEXCEPTION_HPP_
