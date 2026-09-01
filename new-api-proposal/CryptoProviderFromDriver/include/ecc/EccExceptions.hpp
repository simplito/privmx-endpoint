#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECC_EXCEPTIONS_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECC_EXCEPTIONS_HPP_

#include <exception>
#include <initializer_list>
#include <memory>
#include <string>

#include "Exception.hpp"
#include "Exceptions.hpp"
// to be replaced with
// #include <privmx/cryptoservice/ecc/Exception.hpp>

namespace privmx {
namespace cryptoservice {
namespace ecc {

/**
 * Rules for creating exception class names.
 * 
 * Exception class names consist of 4 or 5 parts. 
 * 
 * For the exception class name ABCE, these parts are:
 * A = "Privmx"
 * B = "Cryptoservice" (name of the library)
 * C - is the name of the role (for roles different from KeyProvider)
 *     or is the variant of implementation of assymetric cryptography
 * E = "Exception"
 * 
 * For the exception class name ABCDE, these parts are:
 * A = "Privmx"
 * B = "Cryptoservice" (name of the library)
 * C - is the name of the role (for Random, Digest, Hmac roles)
 *     or the subrole (Encryption or Decryption for SymmetricCryptography role etc.)
 *     or functionality (e.g. EccPublicKey, EccPublicKey or EccPublicKey)
 * D - contain details (e.g. GeneratorFail for the role Random)
 * E = "Exception"
 */

// class PrivmxCryptoserviceEccException : public PrivmxCryptoserviceException {
// public:
//     PrivmxCryptoserviceEccException(
//         const std::string& msg = std::string()
//     ) : PrivmxCryptoserviceException(msg) {}
//     PrivmxCryptoserviceEccException(
//         const char * msg 
//     ) : PrivmxCryptoserviceException(std::string(msg)) {}
// };

// Exceptions for IKeyProvider interface
class PrivmxCryptoserviceEccKeyProviderException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccKeyProviderException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccKeyProviderException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

// Exceptions for IPublicKey interface
class PrivmxCryptoserviceEccPublicKeyException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccPublicKeyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccPublicKeyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccPublicKeyUnknownSignShmException : public PrivmxCryptoserviceEccPublicKeyException {
public:
    PrivmxCryptoserviceEccPublicKeyUnknownSignShmException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccPublicKeyException(msg) {}
    PrivmxCryptoserviceEccPublicKeyUnknownSignShmException(
        const char * msg 
    ) : PrivmxCryptoserviceEccPublicKeyException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccPublicKeyTypeKeyException : public PrivmxCryptoserviceEccPublicKeyException {
public:
    PrivmxCryptoserviceEccPublicKeyTypeKeyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccPublicKeyException(msg) {}
    PrivmxCryptoserviceEccPublicKeyTypeKeyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccPublicKeyException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccPublicKeyExportFormatException : public PrivmxCryptoserviceEccPublicKeyException {
public:
    PrivmxCryptoserviceEccPublicKeyExportFormatException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccPublicKeyException(msg) {}
    PrivmxCryptoserviceEccPublicKeyExportFormatException(
        const char * msg 
    ) : PrivmxCryptoserviceEccPublicKeyException(std::string(msg)) {}
};

// Exceptions for IPrivateKey interface
class PrivmxCryptoserviceEccIPrivateKeyException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccIPrivateKeyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccIPrivateKeyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

// Exceptions for IExtKey interface
class PrivmxCryptoserviceEccExtKeyException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccExtKeyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccExtKeyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

// Exceptions for Base58, Base64 and Utils clases
class PrivmxCryptoserviceEccInvalidBase58ChecksumException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccInvalidBase58ChecksumException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccInvalidBase58ChecksumException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

// Exceptions for legacy kode (from OpenSSL 1.1)
// (BNImpl, PointImpl, ECCImpl clases) - to be rewritted

// Exceptions for ECCImpl class
class PrivmxCryptoserviceEccImplGenerateKeyException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplGenerateKeyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplGenerateKeyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplPoint2OctException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplPoint2OctException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplPoint2OctException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplEcdsaSign2Exception : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplEcdsaSign2Exception(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplEcdsaSign2Exception(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplInvalidSignatureSizeException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplInvalidSignatureSizeException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplInvalidSignatureSizeException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplInvalidSignatureHeaderException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplInvalidSignatureHeaderException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplInvalidSignatureHeaderException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplSignatureCreationException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplSignatureCreationException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplSignatureCreationException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplSignatureConversionException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplSignatureConversionException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplSignatureConversionException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplSignatureSettingException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplSignatureSettingException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplSignatureSettingException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplSignatureVerificationException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplSignatureVerificationException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplSignatureVerificationException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplKeyDerivationException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplKeyDerivationException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplKeyDerivationException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplCreatingEcKeyException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplCreatingEcKeyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplCreatingEcKeyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplCopyEcKeyException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplCopyEcKeyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplCopyEcKeyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplCreatingBnException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplCreatingBnException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplCreatingBnException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplCopyBnException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplCopyBnException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplCopyBnException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplCreatingBnCtxException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplCreatingBnCtxException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplCreatingBnCtxException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplCopyPointException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplCopyPointException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplCopyPointException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplCreatingPointException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplCreatingPointException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplCreatingPointException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplSetPublicKeyException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplSetPublicKeyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplSetPublicKeyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

// class PrivmxCryptoserviceEccImplSetPublicKeyException : public PrivmxCryptoserviceEccException {
// public:
//     PrivmxCryptoserviceEccImplSetPublicKeyException(
//         const std::string& msg = std::string()
//     ) : PrivmxCryptoserviceEccException(msg) {}
//     PrivmxCryptoserviceEccImplSetPublicKeyException(
//         const char * msg 
//     ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
// };

class PrivmxCryptoserviceEccImplSetPrivateKeyException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplSetPrivateKeyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplSetPrivateKeyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplCheckKeyException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplCheckKeyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplCheckKeyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplPointMultiplicationException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplPointMultiplicationException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplPointMultiplicationException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplBnConversionException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplBnConversionException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplBnConversionException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccImplOct2PointConversionException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccImplOct2PointConversionException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccImplOct2PointConversionException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccNotInitializedException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccNotInitializedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccNotInitializedException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

// Exceptions for PointImpl class
class PrivmxCryptoserviceEccPointImplEncodeException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccPointImplEncodeException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccPointImplEncodeException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccPointImplMultiplicationException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccPointImplMultiplicationException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccPointImplMultiplicationException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccPointImplAddException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccPointImplAddException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccPointImplAddException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccPointImplOct2PointException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccPointImplOct2PointException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccPointImplOct2PointException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccPointImplCopyException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccPointImplCopyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccPointImplCopyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccPointImplCreateException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccPointImplCreateException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccPointImplCreateException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccPointImplCreateCtxException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccPointImplCreateCtxException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccPointImplCreateCtxException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccPointEmptyPointException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccPointEmptyPointException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccPointEmptyPointException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

// Exceptions for BNImpl class
class PrivmxCryptoserviceEccBnImplNnModException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccBnImplNnModException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccBnImplNnModException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccBnImplCopyException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccBnImplCopyException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccBnImplCopyException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccBnEmptyBnException : public PrivmxCryptoserviceEccException {
public:
    PrivmxCryptoserviceEccBnEmptyBnException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceEccException(msg) {}
    PrivmxCryptoserviceEccBnEmptyBnException(
        const char * msg 
    ) : PrivmxCryptoserviceEccException(std::string(msg)) {}
};

} // namespace ecc
} // namespace cryptoservice
} // namespace privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECC_EXCEPTIONS_HPP_
