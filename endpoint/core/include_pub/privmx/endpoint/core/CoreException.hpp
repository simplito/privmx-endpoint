#ifndef _PRIVMXLIB_ENDPOINT_CORE_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EXT_EXCEPTION_HPP_

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                            \
    class NAME : public privmx::endpoint::core::Exception {                                                      \
    public:                                                                                                      \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                           \
        NAME(const std::string& description)                                                                     \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), description) {}                 \
        NAME(const std::string& msg, const std::string& name, unsigned int code)                                 \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, std::string()) {}         \
        NAME(const std::string& msg, const std::string& name, unsigned int code, const std::string& description) \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, description) {}           \
        void rethrow() const override;                                                                           \
    };                                                                                                           \
    inline void NAME::rethrow() const {                                                                          \
        throw *this;                                                                                             \
    };

#define DECLARE_ENDPOINT_EXCEPTION(BASE_SCOPED, NAME, MSG, CODE, ...)                                            \
    class NAME : public BASE_SCOPED {                                                                            \
    public:                                                                                                      \
        NAME() : BASE_SCOPED(MSG, #NAME, CODE) {}                                                                \
        NAME(const std::string& new_of_description) : BASE_SCOPED(MSG, #NAME, CODE, new_of_description) {}       \
        void rethrow() const override;                                                                           \
    };                                                                                                           \
    inline void NAME::rethrow() const {                                                                          \
        throw *this;                                                                                             \
    };

namespace privmx {
namespace endpoint {
namespace core {

#define ENDPOINT_CORE_EXCEPTION_CODE 0x00010000
#define ENDPOINT_CORE_API_EXCEPTION_CODE 0x00020000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointCoreException, "Unknown endpoint core exception", "Core", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, NoUserEntryForGivenKeyIdException, "No user entry for given key id", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, InvalidParamsException, "Invalid params", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, InvalidNumberOfParamsException, "Invalid number of params", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, UnsupportedTypeException, "Unsupported type", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, NoHandleFoundException, "No handle found", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, InvalidDataSignatureException, "Invalid data signature", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, UnsupportedSerializerBinaryFormatException, "Unsupported serializer binary format option", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, NotImplementedException, "Not Implemented", 0x000A)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, InvalidMethodException, "Invalid method", 0x000B)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, InvalidArgumentTypeException, "Invalid argument type", 0x000C)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, InvalidBackendRequestModeException, "Invalid BackendRequest mode", 0x000D)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, UserVerificationFailureException, "User verification failure", 0x000E)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, UserVerificationMethodUnhandledException, "UserVerifierInterface.verify() thrown an exception. Implementation of the UserVerifierInterface should provide adequate error handling.", 0x000F)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, MalformedEncryptionKeyException, "Malformed encryption key", 0x0010)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, UnknownEncryptionKeyVersionException, "Unknown encryption key", 0x0011)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, EncryptionKeyContainerValidationException, "Encryption key container validation error", 0x0012)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, DataIntegrityObjectDuplicatedException, "Duplicated data integrity object", 0x0013)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, MalformedDataIntegrityObjectException, "Malformed data integrity object", 0x0014)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, InvalidDataIntegrityObjectChecksumException, "Invalid data integrity object checksum", 0x0015)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, DataIntegrityObjectMismatchEncKeyException, "User key does not match with author public key in data integrity object", 0x0016)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, DataIntegrityObjectInvalidSignatureException, "Invalid data integrity object signature", 0x0017)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, KeyProviderRequestCompletedException, "KeyProvider request completed", 0x0018)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, MalformedVerifierResponseException, "Malformed verifier response", 0x0019)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, UnknownModuleEncryptionKeyException, "Module's enc key with given keyId does not exist.", 0x0020)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, ModulePublicDataMismatchException, "Module public data mismatch", 0x0021)
DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, InvalidEncryptedModuleDataVersionException, "Invalid version of encrypted module data", 0x0022)

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointConnectionException, "Unknown endpoint connection exception", "Connection", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointConnectionException, NotInitializedException, "Endpoint not initialized", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointConnectionException, CannotExtractLibPlatformDisconnectedEventException, "Cannot extract LibPlatformDisconnectedEvent", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointConnectionException, CannotExtractLibConnectedEventException, "Cannot extract LibConnectedEvent", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointConnectionException, CannotExtractLibDisconnectedEventException, "Cannot extract LibDisconnectedEvent", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointConnectionException, DataBiggerThanDeclaredException, "Data bigger than declared", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointConnectionException, DataSmallerThanDeclaredException, "Data smaller than declared", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointConnectionException, DataDifferentThanDeclaredException, "Data different than declared", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointConnectionException, CannotExtractLibBreakEventException, "Cannot extract LibBreakEvent", 0x0008)
DECLARE_ENDPOINT_EXCEPTION(EndpointConnectionException, ServerVersionMismatchException, "The Bridge Server and the PrivMX Endpoint library versions mismatch", 0x0009)

} // core
} // endpoint
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_CORE_EXT_EXCEPTION_HPP_