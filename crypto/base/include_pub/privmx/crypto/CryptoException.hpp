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

// Only conditions this library can still raise. The codes are explicit and the surviving ones keep
// the values they had, so a client matching on a number is not silently handed a different meaning;
// the gaps are where BIP-39, SRP, the big-number and point wrappers, the legacy ExtKey, the two
// crypto drivers and both halves of the legacy frame used to be. An exception class nobody throws
// is worse than a missing one: it invites a `catch` for a case that cannot happen, which then reads
// as handled.
//
// 0x0009 and 0x000A went with the legacy reader: "missing iv" and "unknown decryption type" were
// both diagnoses of its leading `CipherType` byte, and nothing reads that byte any more.
// 0x0016 went with it too — the signature it reported missing was the legacy frame's own.
// 0x0026..0x0028 named OpenSSL and the two privmxDrv* crypto drivers, which no longer exist;
// pmx-crypto reports its own failures through the surviving codes.
#define CRYPTO_EXCEPTIONS(X)                                                                                          \
    X(UnsupportedKeyFormatException, "Unsupported key format", 0x0001)                                                \
    X(InvalidSignatureSizeException, "Invalid signature size", 0x0003)                                                \
    X(InvalidSignatureHeaderException, "Invalid signature header", 0x0004)                                            \
    X(ECCIsNotInitializedException, "ECC is not initialized", 0x0005)                                                 \
    X(WrongMessageSecurityTagException, "Wrong message security tag", 0x0007)                                         \
    X(DecryptInvalidKeyLengthException, "Decrypt invalid key length", 0x0008)                                         \
    X(UnsupportedHashAlgorithmException, "Unsupported hash algorithm", 0x000B)                                        \
    X(CryptoNotImplementedException, "Not implemented", 0x000C)                                                       \
    X(InvalidChecksumException, "Invalid checksum", 0x0010)                                                           \
    X(EncryptInvalidKeyLengthException, "Encrypt invalid key length", 0x0011)                                         \
    X(IncorrectParamsException, "Incorrect params", 0x001B)                                                           \
    X(InvalidHandshakeStateException, "Invalid handshake state", 0x001C)                                              \
    X(InvalidNetworkException, "Invalid network", 0x0023)                                                             \
    X(InvalidCompressionFlagException, "Invalid compression flag", 0x0024)                                            \
    X(InvalidWIFPayloadLengthException, "Invalid WIF payload length", 0x0025)                                         \
    /* pmx-crypto's own failure modes, mapped by CryptoErrors::rethrow. They start at 0x002B, where  */ \
    /* the deleted BIP32 size check used to be, so none of the surviving codes above had to move.    */ \
    X(RandomGeneratorFailureException, "Random generator failure", 0x002B)                                            \
    X(DigestFailureException, "Digest computation failure", 0x002C)                                                   \
    X(HmacFailureException, "HMAC computation failure", 0x002D)                                                       \
    X(KdfFailureException, "Key derivation failure", 0x002E)                                                          \
    X(SymmetricCipherFailureException, "Symmetric cipher failure", 0x002F)                                            \
    X(EccOperationFailureException, "ECC operation failure", 0x0030)                                                  \
    X(AsymmetricKeyFailureException, "Asymmetric key operation failure", 0x0031)

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
