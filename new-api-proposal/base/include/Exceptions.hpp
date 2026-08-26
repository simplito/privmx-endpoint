#ifndef _PRIVMXLIB_CRYPTOSERVICE_EXCEPTIONS_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_EXCEPTIONS_HPP_

#include <exception>
#include <initializer_list>
#include <memory>
#include <string>

#include "Exception.hpp"
// to be replaced with
// #include <privmx/cryptoservice/Exception.hpp>

namespace privmx {
namespace cryptoservice {
// namespace core {

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

class PrivmxCryptoserviceException : public Exception {
public:
    PrivmxCryptoserviceException(
        const std::string& msg = std::string(),
        const std::string& name = std::string(),
        const std::string& scope = std::string(),
        unsigned int code = 0,
        const std::string& description = std::string()
    ) : Exception(msg, name, scope, code, description) {}
};

class PrivmxCryptoserviceRandomException : public PrivmxCryptoserviceException {
public:
    PrivmxCryptoserviceRandomException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceException(msg) {}
    PrivmxCryptoserviceRandomException(
        const char * msg 
    ) : PrivmxCryptoserviceException(std::string(msg)) {}
};

class PrivmxCryptoserviceDigestException : public PrivmxCryptoserviceException {
public:
    PrivmxCryptoserviceDigestException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceException(msg) {}
    PrivmxCryptoserviceDigestException(
        const char * msg 
    ) : PrivmxCryptoserviceException(std::string(msg)) {}
};

class PrivmxCryptoserviceHmacException : public PrivmxCryptoserviceException {
public:
    PrivmxCryptoserviceHmacException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceException(msg) {}
    PrivmxCryptoserviceHmacException(
        const char * msg 
    ) : PrivmxCryptoserviceException(std::string(msg)) {}
};

class PrivmxCryptoserviceKdfException : public PrivmxCryptoserviceException {
public:
    PrivmxCryptoserviceKdfException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceException(msg) {}
    PrivmxCryptoserviceKdfException(
        const char * msg 
    ) : PrivmxCryptoserviceException(std::string(msg)) {}
};

class PrivmxCryptoserviceSymmetricCipherException : public PrivmxCryptoserviceException {
public:
    PrivmxCryptoserviceSymmetricCipherException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceException(msg) {}
    PrivmxCryptoserviceSymmetricCipherException(
        const char * msg 
    ) : PrivmxCryptoserviceException(std::string(msg)) {}
};

class PrivmxCryptoserviceEccException : public PrivmxCryptoserviceException {
public:
    PrivmxCryptoserviceEccException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceException(msg) {}
    PrivmxCryptoserviceEccException(
        const char * msg 
    ) : PrivmxCryptoserviceException(std::string(msg)) {}
};

// Exceptions for IRandom interface
class PrivmxCryptoserviceRandomGeneratorFailException : public PrivmxCryptoserviceRandomException {
public:
    PrivmxCryptoserviceRandomGeneratorFailException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceRandomException(msg) {}
    PrivmxCryptoserviceRandomGeneratorFailException(
        const char * msg 
    ) : PrivmxCryptoserviceRandomException(std::string(msg)) {}
};

// Exceptions for IDigest interface
class PrivmxCryptoserviceDigestUnknownProtocolException : public PrivmxCryptoserviceDigestException {
public:
    PrivmxCryptoserviceDigestUnknownProtocolException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceDigestException(msg) {}
    PrivmxCryptoserviceDigestUnknownProtocolException(
        const char * msg 
    ) : PrivmxCryptoserviceDigestException(std::string(msg)) {}
};

class PrivmxCryptoserviceDigestUnableFetchProtocolException : public PrivmxCryptoserviceDigestException {
public:
    PrivmxCryptoserviceDigestUnableFetchProtocolException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceDigestException(msg) {}
    PrivmxCryptoserviceDigestUnableFetchProtocolException(
        const char * msg 
    ) : PrivmxCryptoserviceDigestException(std::string(msg)) {}
};

class PrivmxCryptoserviceDigestUnableSetContextException : public PrivmxCryptoserviceDigestException {
public:
    PrivmxCryptoserviceDigestUnableSetContextException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceDigestException(msg) {}
    PrivmxCryptoserviceDigestUnableSetContextException(
        const char * msg 
    ) : PrivmxCryptoserviceDigestException(std::string(msg)) {}
};

class PrivmxCryptoserviceDigestInitializationFailedException : public PrivmxCryptoserviceDigestException {
public:
    PrivmxCryptoserviceDigestInitializationFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceDigestException(msg) {}
    PrivmxCryptoserviceDigestInitializationFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceDigestException(std::string(msg)) {}
};

class PrivmxCryptoserviceDigestUpdateFailedException : public PrivmxCryptoserviceDigestException {
public:
    PrivmxCryptoserviceDigestUpdateFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceDigestException(msg) {}
    PrivmxCryptoserviceDigestUpdateFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceDigestException(std::string(msg)) {}
};

class PrivmxCryptoserviceDigestFinalizationFailedException : public PrivmxCryptoserviceDigestException {
public:
    PrivmxCryptoserviceDigestFinalizationFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceDigestException(msg) {}
    PrivmxCryptoserviceDigestFinalizationFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceDigestException(std::string(msg)) {}
};

// Exceptions for IHmac interface
class PrivmxCryptoserviceHmacUnknownProtocolException : public PrivmxCryptoserviceHmacException {
public:
    PrivmxCryptoserviceHmacUnknownProtocolException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceHmacException(msg) {}
    PrivmxCryptoserviceHmacUnknownProtocolException(
        const char * msg 
    ) : PrivmxCryptoserviceHmacException(std::string(msg)) {}
};

class PrivmxCryptoserviceHmacUnableFetchProtocolException : public PrivmxCryptoserviceHmacException {
public:
    PrivmxCryptoserviceHmacUnableFetchProtocolException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceHmacException(msg) {}
    PrivmxCryptoserviceHmacUnableFetchProtocolException(
        const char * msg 
    ) : PrivmxCryptoserviceHmacException(std::string(msg)) {}
};

class PrivmxCryptoserviceHmacUnableSetContextException : public PrivmxCryptoserviceHmacException {
public:
    PrivmxCryptoserviceHmacUnableSetContextException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceHmacException(msg) {}
    PrivmxCryptoserviceHmacUnableSetContextException(
        const char * msg 
    ) : PrivmxCryptoserviceHmacException(std::string(msg)) {}
};

class PrivmxCryptoserviceHmacInitializationFailedException : public PrivmxCryptoserviceHmacException {
public:
    PrivmxCryptoserviceHmacInitializationFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceHmacException(msg) {}
    PrivmxCryptoserviceHmacInitializationFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceHmacException(std::string(msg)) {}
};

class PrivmxCryptoserviceHmacUpdateFailedException : public PrivmxCryptoserviceHmacException {
public:
    PrivmxCryptoserviceHmacUpdateFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceHmacException(msg) {}
    PrivmxCryptoserviceHmacUpdateFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceHmacException(std::string(msg)) {}
};

class PrivmxCryptoserviceHmacFinalizationFailedException : public PrivmxCryptoserviceHmacException {
public:
    PrivmxCryptoserviceHmacFinalizationFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceHmacException(msg) {}
    PrivmxCryptoserviceHmacFinalizationFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceHmacException(std::string(msg)) {}
};

// Exceptions for ISymmetricCipher interface
class PrivmxCryptoserviceEncryptionUnknownProtocolException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceEncryptionUnknownProtocolException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceEncryptionUnknownProtocolException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceEncryptionUnableFetchProtocolException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceEncryptionUnableFetchProtocolException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceEncryptionUnableFetchProtocolException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceEncryptionUnableSetContextException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceEncryptionUnableSetContextException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceEncryptionUnableSetContextException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceEncryptionInitializationFailedException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceEncryptionInitializationFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceEncryptionInitializationFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceEncryptionPaddingException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceEncryptionPaddingException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceEncryptionPaddingException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceEncryptionUpdateFailedException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceEncryptionUpdateFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceEncryptionUpdateFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceEncryptionFinalizationFailedException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceEncryptionFinalizationFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceEncryptionFinalizationFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

// only for AES 256 GCM encryption with AAC and tag
class PrivmxCryptoserviceEncryptionAacUpdateFailedException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceEncryptionAacUpdateFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceEncryptionAacUpdateFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

// only for AES 256 GCM encryption with AAC and tag
class PrivmxCryptoserviceEncryptionTagExtractionFailedException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceEncryptionTagExtractionFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceEncryptionTagExtractionFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceDecryptionUnknownProtocolException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceDecryptionUnknownProtocolException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceDecryptionUnknownProtocolException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceDecryptionUnableFetchProtocolException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceDecryptionUnableFetchProtocolException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceDecryptionUnableFetchProtocolException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceDecryptionUnableSetContextException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceDecryptionUnableSetContextException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceDecryptionUnableSetContextException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceDecryptionInitializationFailedException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceDecryptionInitializationFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceDecryptionInitializationFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceDecryptionPaddingException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceDecryptionPaddingException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceDecryptionPaddingException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceDecryptionUpdateFailedException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceDecryptionUpdateFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceDecryptionUpdateFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

class PrivmxCryptoserviceDecryptionFinalizationFailedException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceDecryptionFinalizationFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceDecryptionFinalizationFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

// only for AES 256 GCM encryption with AAC and tag
class PrivmxCryptoserviceDecryptionAacUpdateFailedException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceDecryptionAacUpdateFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceDecryptionAacUpdateFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

// only for AES 256 GCM encryption with AAC and tag
class PrivmxCryptoserviceDecryptionInvalidTagException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceDecryptionInvalidTagException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceDecryptionInvalidTagException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

// only for AES 256 GCM encryption with AAC and tag
class PrivmxCryptoserviceDecryptionTagSettingFailedException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceDecryptionTagSettingFailedException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceDecryptionTagSettingFailedException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

// only for AES 256 CBC + HMAC 256
class PrivmxCryptoserviceDecryptionWrongMessageSecurityTagException : public PrivmxCryptoserviceSymmetricCipherException {
public:
    PrivmxCryptoserviceDecryptionWrongMessageSecurityTagException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
    PrivmxCryptoserviceDecryptionWrongMessageSecurityTagException(
        const char * msg 
    ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
};

// class PrivmxCryptoserviceDecryptionException : public PrivmxCryptoserviceSymmetricCipherException {
// public:
//     PrivmxCryptoserviceDecryptionException(
//         const std::string& msg = std::string()
//     ) : PrivmxCryptoserviceSymmetricCipherException(msg) {}
//     PrivmxCryptoserviceDecryptionException(
//         const char * msg 
//     ) : PrivmxCryptoserviceSymmetricCipherException(std::string(msg)) {}
// };

// Exceptions for IKdf interface
class PrivmxCryptoserviceKdfUnknownProtocolException : public PrivmxCryptoserviceKdfException {
public:
    PrivmxCryptoserviceKdfUnknownProtocolException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceKdfException(msg) {}
    PrivmxCryptoserviceKdfUnknownProtocolException(
        const char * msg 
    ) : PrivmxCryptoserviceKdfException(std::string(msg)) {}
};

class PrivmxCryptoserviceKdfUnableFetchProtocolException : public PrivmxCryptoserviceKdfException {
public:
    PrivmxCryptoserviceKdfUnableFetchProtocolException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceKdfException(msg) {}
    PrivmxCryptoserviceKdfUnableFetchProtocolException(
        const char * msg 
    ) : PrivmxCryptoserviceKdfException(std::string(msg)) {}
};

class PrivmxCryptoserviceKdfUnableGetHmacException : public PrivmxCryptoserviceKdfException {
public:
    PrivmxCryptoserviceKdfUnableGetHmacException(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceKdfException(msg) {}
    PrivmxCryptoserviceKdfUnableGetHmacException(
        const char * msg 
    ) : PrivmxCryptoserviceKdfException(std::string(msg)) {}
};

class PrivmxCryptoserviceKdf1Exception : public PrivmxCryptoserviceKdfException {
public:
    PrivmxCryptoserviceKdf1Exception(
        const std::string& msg = std::string()
    ) : PrivmxCryptoserviceKdfException(msg) {}
    PrivmxCryptoserviceKdf1Exception(
        const char * msg 
    ) : PrivmxCryptoserviceKdfException(std::string(msg)) {}
};

// } // namespace core
} // namespace cryptoservice
} // namespace privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_EXCEPTIONS_HPP_
