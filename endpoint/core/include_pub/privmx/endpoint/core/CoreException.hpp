#ifndef _PRIVMXLIB_ENDPOINT_CORE_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EXT_EXCEPTION_HPP_

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                                  \
    class NAME : public privmx::endpoint::core::Exception {                                                            \
    public:                                                                                                            \
        static constexpr unsigned int SCOPE_CODE = (CODE);                                                             \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                                 \
        NAME(const std::string& description)                                                                           \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), description) {}                       \
        NAME(const std::string& msg, const std::string& name, unsigned int code)                                       \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, std::string()) {}               \
        NAME(const std::string& msg, const std::string& name, unsigned int code, const std::string& description)       \
            : privmx::endpoint::core::Exception(msg, name, SCOPE, (CODE << 16) | code, description) {}                 \
        void rethrow() const override;                                                                                 \
    };                                                                                                                 \
    inline void NAME::rethrow() const {                                                                                \
        throw *this;                                                                                                   \
    };

#define DECLARE_ENDPOINT_EXCEPTION(BASE_SCOPED, NAME, MSG, CODE, ...)                                                  \
    class NAME : public BASE_SCOPED {                                                                                  \
    public:                                                                                                            \
        static constexpr unsigned int FULL_CODE = (BASE_SCOPED::SCOPE_CODE << 16) | (CODE);                            \
        NAME() : BASE_SCOPED(MSG, #NAME, CODE) {}                                                                      \
        NAME(const std::string& new_of_description) : BASE_SCOPED(MSG, #NAME, CODE, new_of_description) {}             \
        void rethrow() const override;                                                                                 \
    };                                                                                                                 \
    inline void NAME::rethrow() const {                                                                                \
        throw *this;                                                                                                   \
    };

namespace privmx {
namespace endpoint {
namespace core {
// clang-format off
#define ENDPOINT_CORE_EXCEPTION_CODE 0x00010000
#define ENDPOINT_CORE_API_EXCEPTION_CODE 0x00020000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointCoreException, "Unknown endpoint core exception", "Core", 0x0001)

#define CORE_EXCEPTIONS(X)                                                                                            \
    X(InvalidParamsException, "Invalid params", 0x0002)                                                               \
    X(InvalidNumberOfParamsException, "Invalid number of params", 0x0003)                                             \
    X(UnsupportedTypeException, "Unsupported type", 0x0004)                                                           \
    X(NoHandleFoundException, "No handle found", 0x0005)                                                              \
    X(InvalidDataSignatureException, "Invalid data signature", 0x0007)                                                \
    X(UnsupportedSerializerBinaryFormatException, "Unsupported serializer binary format option", 0x0009)              \
    X(NotImplementedException, "Not Implemented", 0x000A)                                                             \
    X(InvalidMethodException, "Invalid method", 0x000B)                                                               \
    X(InvalidArgumentTypeException, "Invalid argument type", 0x000C)                                                  \
    X(InvalidBackendRequestModeException, "Invalid BackendRequest mode", 0x000D)                                      \
    X(UserVerificationFailureException, "User verification failure", 0x000E)                                          \
    X(UserVerificationMethodUnhandledException, "UserVerifierInterface.verify() thrown an exception. Implementation of the UserVerifierInterface should provide adequate error handling.", 0x000F) \
    X(MalformedEncryptionKeyException, "Malformed encryption key", 0x0010)                                            \
    X(UnknownEncryptionKeyVersionException, "Unknown encryption key", 0x0011)                                         \
    X(EncryptionKeyContainerValidationException, "Encryption key container validation error", 0x0012)                 \
    X(DataIntegrityObjectDuplicatedException, "Duplicated data integrity object", 0x0013)                             \
    X(MalformedDataIntegrityObjectException, "Malformed data integrity object", 0x0014)                               \
    X(InvalidDataIntegrityObjectChecksumException, "Invalid data integrity object checksum", 0x0015)                  \
    X(DataIntegrityObjectMismatchEncKeyException, "User key does not match with author public key in data integrity object", 0x0016) \
    X(DataIntegrityObjectInvalidSignatureException, "Invalid data integrity object signature", 0x0017)                \
    X(KeyProviderRequestCompletedException, "KeyProvider request completed", 0x0018)                                  \
    X(MalformedVerifierResponseException, "Malformed verifier response", 0x0019)                                      \
    X(UnknownModuleEncryptionKeyException, "Module's enc key with given keyId does not exist.", 0x0020)               \
    X(ModulePublicDataMismatchException, "Module public data mismatch", 0x0021)                                       \
    X(InvalidEncryptedModuleDataVersionException, "Invalid version of encrypted module data", 0x0022)                 \
    X(InvalidSubscriptionQueryException, "Invalid subscriptionQuery", 0x00024)                                        \
    X(InvalidSingletonsHolderStateException, "Invalid Singletons Holder state", 0x00025)                              \
    X(EncryptionKeyValidationException, "Encryption key validation error", 0x0027)                                    \
    X(IncorrectKeyIdFormatException, "Incorrect key id format", 0x0028)

#define PRIVMX_CORE_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointCoreException, NAME, MSG, CODE)
CORE_EXCEPTIONS(PRIVMX_CORE_DECLARE)
#undef PRIVMX_CORE_DECLARE

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointConnectionException, "Unknown endpoint connection exception", "Connection", 0x0002)

#define CONNECTION_EXCEPTIONS(X)                                                                                      \
    X(NotInitializedException, "Endpoint not initialized", 0x0001)                                                    \
    X(CannotExtractLibPlatformDisconnectedEventException, "Cannot extract LibPlatformDisconnectedEvent", 0x0002)      \
    X(CannotExtractLibConnectedEventException, "Cannot extract LibConnectedEvent", 0x0003)                            \
    X(CannotExtractLibDisconnectedEventException, "Cannot extract LibDisconnectedEvent", 0x0004)                      \
    X(DataBiggerThanDeclaredException, "Data bigger than declared", 0x0005)                                           \
    X(DataSmallerThanDeclaredException, "Data smaller than declared", 0x0006)                                         \
    X(DataDifferentThanDeclaredException, "Data different than declared", 0x0007)                                     \
    X(CannotExtractLibBreakEventException, "Cannot extract LibBreakEvent", 0x0008)                                    \
    X(ServerVersionMismatchException, "The Bridge Server and the PrivMX Endpoint library versions mismatch", 0x0009)  \
    X(CannotExtractCollectionChangedEventException, "Cannot extract CollectionChangedEvent", 0x000A)                  \
    X(CannotExtractContextUserAddedEventException, "Cannot extract ContextUserAddedEvent", 0x000B)                    \
    X(CannotExtractContextUserRemovedEventException, "Cannot extract ContextUserRemovedEvent", 0x000C)                \
    X(CannotExtractContextUsersStatusChangedEventException, "Cannot extract ContextUsersStatusChangedEvent", 0x000D)  \
    X(NotConnectedException, "Endpoint is not connected or not initialized", 0x000E)

#define PRIVMX_CONNECTION_DECLARE(NAME, MSG, CODE) DECLARE_ENDPOINT_EXCEPTION(EndpointConnectionException, NAME, MSG, CODE)
CONNECTION_EXCEPTIONS(PRIVMX_CONNECTION_DECLARE)
#undef PRIVMX_CONNECTION_DECLARE

// compile-time guard: codes are collected from the lists above, never retyped
#define PRIVMX_CODE(NAME, MSG, CODE) NAME::FULL_CODE,
static_assert(
    privmx::endpoint::core::exceptionCodesUnique({
        CORE_EXCEPTIONS(PRIVMX_CODE)
        CONNECTION_EXCEPTIONS(PRIVMX_CODE)
    }),
    "Duplicate exception code in core scope"
);
#undef PRIVMX_CODE
#undef CORE_EXCEPTIONS
#undef CONNECTION_EXCEPTIONS
// clang-format on
} // namespace core
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_CORE_EXT_EXCEPTION_HPP_
