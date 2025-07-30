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

DECLARE_PRIVMX_EXCEPTION_CHILD(UnsupportedKeyFormatException, CryptoException, "Unsupported key format.", 0x0001)
DECLARE_PRIVMX_EXCEPTION_CHILD(EmptyPointException, CryptoException, "Empty point", 0x0002)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidSignatureSizeException, CryptoException, "Invalid signature size", 0x0003)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidSignatureHeaderException, CryptoException, "Invalid signature header", 0x0004)
DECLARE_PRIVMX_EXCEPTION_CHILD(ECCIsNotInitializedException, CryptoException, "ECC is not initialized", 0x0005)
DECLARE_PRIVMX_EXCEPTION_CHILD(EmptyBNException, CryptoException, "Empty BN", 0x0006)
DECLARE_PRIVMX_EXCEPTION_CHILD(WrongMessageSecurityTagException, CryptoException, "Wrong message security tag", 0x0007)
DECLARE_PRIVMX_EXCEPTION_CHILD(DecryptInvalidKeyLengthException, CryptoException, "Decrypt invalid key length", 0x0008)
DECLARE_PRIVMX_EXCEPTION_CHILD(MissingIvException, CryptoException, "Missing iv", 0x0009)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnknownDecryptionTypeException, CryptoException, "Unknown decryption type", 0x000A)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnsupportedHashAlgorithmException, CryptoException, "Unsupported hash algorithm", 0x000B)
DECLARE_PRIVMX_EXCEPTION_CHILD(NotImplementedException, CryptoException, "Not implemented", 0x000C)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidStrengthException, CryptoException, "Invalid strength", 0x000D)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidEntropyException, CryptoException, "Invalid entropy", 0x000E)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidMnemonicException, CryptoException, "Invalid mnemonic", 0x000F)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidChecksumException, CryptoException, "Invalid checksum", 0x0010)
DECLARE_PRIVMX_EXCEPTION_CHILD(EncryptInvalidKeyLengthException, CryptoException, "Encrypt invalid key length", 0x0011)
DECLARE_PRIVMX_EXCEPTION_CHILD(OnlyHmacSHA256WithIvIsSupportedForAES256CBCException, CryptoException, "Only hmac SHA-256 with iv is supported for AES-256-CBC", 0x0012)
DECLARE_PRIVMX_EXCEPTION_CHILD(CannotPassIvToDeterministicAES256CBCHmacSHA256Exception, CryptoException, "Cannot pass iv to deterministic AES-256-CBC hmac SHA-256", 0x0013)
DECLARE_PRIVMX_EXCEPTION_CHILD(XTEAECBEncryptionDoesntSupportHmacAndIvException, CryptoException, "XTEA-ECB encryption doesn't support hmac and iv", 0x0014)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnsupportedEncryptionAlgorithmException, CryptoException, "Unsupported encryption algorithm", 0x0015)
DECLARE_PRIVMX_EXCEPTION_CHILD(MissingRequiredSignatureException, CryptoException, "Missing required signature", 0x0016)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidFirstByteOfCipherException, CryptoException, "Invalid first byte of cipher", 0x0017)
DECLARE_PRIVMX_EXCEPTION_CHILD(GivenPrivKeyDoesNotMatchException, CryptoException, "Given priv key does not match", 0x0018)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnsupportedAlgorithmException, CryptoException, "Unsupported algorithm", 0x0019)
DECLARE_PRIVMX_EXCEPTION_CHILD(UnsupportedVersionException, CryptoException, "Unsupported version", 0x001A)
DECLARE_PRIVMX_EXCEPTION_CHILD(IncorrectParamsException, CryptoException, "Incorrect params", 0x001B)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidHandshakeStateException, CryptoException, "Invalid handshake state", 0x001C)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidBNException, CryptoException, "Invalid B N", 0x001D)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidM2Exception, CryptoException, "Invalid M2", 0x0001E)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidVersionException, CryptoException, "Invalid version", 0x001F)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidParentFingerprintException, CryptoException, "Invalid parent fingerprint", 0x0020)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidResultSizeException, CryptoException, "Invalid result size", 0x0022)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidNetworkException, CryptoException, "Invalid network", 0x0023)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidCompressionFlagException, CryptoException, "Invalid compression flag", 0x0024)
DECLARE_PRIVMX_EXCEPTION_CHILD(InvalidWIFPayloadLengthException, CryptoException, "Invalid WIF payload length", 0x0025)
DECLARE_PRIVMX_EXCEPTION_CHILD(OpenSSLException, CryptoException, "OpenSSL Exception", 0x0026)
DECLARE_PRIVMX_EXCEPTION_CHILD(PrivmxDriverCryptoException, CryptoException, "privmxDrvCrypto Exception", 0x0027)
DECLARE_PRIVMX_EXCEPTION_CHILD(PrivmxDriverEccException, CryptoException, "privmxDrvEcc Exception", 0x0028)
DECLARE_PRIVMX_EXCEPTION_CHILD(GivenPublicKeyDoesNotMatchWithSignatureException, CryptoException, "Given public key does not match with signature", 0x0029)
DECLARE_PRIVMX_EXCEPTION_CHILD(ExtKeyDoesNotHoldPrivateKeyException, CryptoException, "Ext key does not hold private key", 0x002A)

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_CRYPTOEXCEPTION_HPP_
