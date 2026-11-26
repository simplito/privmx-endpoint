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

namespace privmx {
namespace crypto {

DECLARE_PRIVMX_EXCEPTION(CryptoException, utils::BaseException, "Crypto exception", 0x00A1)

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
DECLARE_PRIVMX_EXCEPTION_CHILD(UnsupportedKeyFormatException, CryptoException, "Unsupported key format.", 0x0001)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidSignatureSizeException, CryptoException, "Invalid signature size", 0x0003)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidSignatureHeaderException, CryptoException, "Invalid signature header", 0x0004)
DECLARE_PRIVMX_EXCEPTION_CHILD(ECCIsNotInitializedException, CryptoException, "ECC is not initialized", 0x0005)
DECLARE_PRIVMX_EXCEPTION_CHILD(WrongMessageSecurityTagException, CryptoException, "Wrong message security tag", 0x0007)
DECLARE_PRIVMX_EXCEPTION_CHILD(DecryptInvalidKeyLengthException, CryptoException, "Decrypt invalid key length", 0x0008)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnsupportedHashAlgorithmException, CryptoException, "Unsupported hash algorithm", 0x000B)
DECLARE_PRIVMX_EXCEPTION_CHILD(NotImplementedException, CryptoException, "Not implemented", 0x000C)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidChecksumException, CryptoException, "Invalid checksum", 0x0010)
DECLARE_PRIVMX_EXCEPTION_CHILD(EncryptInvalidKeyLengthException, CryptoException, "Encrypt invalid key length", 0x0011)
DECLARE_PRIVMX_EXCEPTION_CHILD(IncorrectParamsException, CryptoException, "Incorrect params", 0x001B)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidHandshakeStateException, CryptoException, "Invalid handshake state", 0x001C)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidNetworkException, CryptoException, "Invalid network", 0x0023)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidCompressionFlagException, CryptoException, "Invalid compression flag", 0x0024)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidWIFPayloadLengthException, CryptoException, "Invalid WIF payload length", 0x0025)


} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_CRYPTOEXCEPTION_HPP_
