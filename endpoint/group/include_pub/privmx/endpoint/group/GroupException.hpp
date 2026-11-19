#ifndef _PRIVMXLIB_ENDPOINT_GROUP_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_EXT_EXCEPTION_HPP_

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                                  \
    class NAME : public privmx::endpoint::core::Exception {                                                            \
    public:                                                                                                            \
        static constexpr unsigned int SCOPE_CODE = (CODE);                                                             \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                                 \
        NAME(std::string description)                                                                                  \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), std::move(description)) {}            \
        NAME(const Exception& cause)                                                                                   \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), std::string(), cause) {}              \
        NAME(std::string description, const Exception& cause)                                                          \
            : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16), std::move(description), cause) {}     \
        NAME(std::string msg, std::string_view name, unsigned int code)                                                \
            : privmx::endpoint::core::Exception(std::move(msg), name, SCOPE, (CODE << 16) | code, std::string()) {}    \
        NAME(std::string msg, std::string_view name, unsigned int code, std::string description)                       \
            : privmx::endpoint::core::Exception(                                                                       \
                  std::move(msg),                                                                                      \
                  name,                                                                                                \
                  SCOPE,                                                                                               \
                  (CODE << 16) | code,                                                                                 \
                  std::move(description)                                                                               \
              ) {}                                                                                                     \
        NAME(std::string msg, std::string_view name, unsigned int code, const Exception& cause)                        \
            : privmx::endpoint::core::Exception(                                                                       \
                  std::move(msg),                                                                                      \
                  name,                                                                                                \
                  SCOPE,                                                                                               \
                  (CODE << 16) | code,                                                                                 \
                  std::string(),                                                                                       \
                  cause                                                                                                \
              ) {}                                                                                                     \
        NAME(                                                                                                          \
            std::string msg,                                                                                           \
            std::string_view name,                                                                                     \
            unsigned int code,                                                                                         \
            std::string description,                                                                                   \
            const Exception& cause                                                                                     \
        )                                                                                                              \
            : privmx::endpoint::core::Exception(                                                                       \
                  std::move(msg),                                                                                      \
                  name,                                                                                                \
                  SCOPE,                                                                                               \
                  (CODE << 16) | code,                                                                                 \
                  std::move(description),                                                                              \
                  cause                                                                                                \
              ) {}                                                                                                     \
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
        NAME(std::string new_of_description) : BASE_SCOPED(MSG, #NAME, CODE, std::move(new_of_description)) {}         \
        NAME(const Exception& cause) : BASE_SCOPED(MSG, #NAME, CODE, std::string(), cause) {}                          \
        NAME(std::string new_of_description, const Exception& cause)                                                   \
            : BASE_SCOPED(MSG, #NAME, CODE, std::move(new_of_description), cause) {}                                   \
        void rethrow() const override;                                                                                 \
    };                                                                                                                 \
    inline void NAME::rethrow() const {                                                                                \
        throw *this;                                                                                                   \
    };
namespace privmx {
namespace endpoint {
namespace group {
// clang-format off
#define ENDPOINT_GROUP_EXCEPTION_CODE 0x000D0000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointGroupException, "Unknown endpoint group exception", "Group", 0x000D)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, NotInitializedException, "Endpoint not initialized", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, CannotExtractGroupCreatedEventException, "Cannot extract GroupCreatedEvent", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, CannotExtractGroupUpdatedEventException, "Cannot extract GroupUpdatedEvent", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, CannotExtractGroupDeletedEventException, "Cannot extract GroupDeletedEvent", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, AlreadySubscribedException, "Already subscribed", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, NotSubscribedException, "Cannot unsubscribe if not subscribed", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, InvalidEncryptedGroupDataVersionException, "Invalid version of encrypted group data", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, UnknownGroupFormatException, "Unknown Group format", 0x0008)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupPublicDataMismatchException, "Group public data mismatch", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupDataIntegrityException, "Failed group data integrity check", 0x000A)
// 0x000B: reserved, no longer thrown; kept so the code is not reused.
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupChainBrokenException, "Group version chain link broken", 0x000B)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupUnauthorizedSignerException, "Group commit signer not allowed by group policy", 0x000C)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupMembershipMismatchException, "Group membership in signed data does not match bridge-served fields", 0x000D)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, InvalidSubscriptionQueryException, "Invalid subscriptionQuery", 0x000E)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, RotatedAlreadyException, "Concurrent group commit; retries exhausted", 0x000F)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupHistoryForkException, "Group history diverged from a previously verified state (version or keyVersion regressed)", 0x0010)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, IncompleteEpochLadderException, "Rotation aborted: the epoch ladder rung set for the new epoch would be incomplete", 0x0011)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, InvalidEnvelopeFormatException, "Malformed group envelope", 0x0012)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeTruncatedFileException, "Encrypted file is shorter than its envelope declares", 0x0013)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, CannotExtractGroupCustomEventException, "Cannot extract GroupCustomEvent", 0x0014)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeWrongLocationException, "Envelope was written for another location", 0x0015)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeWrongKindException, "Envelope is not the kind this call reads", 0x0016)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeNotARecipientException, "Caller is not among the envelope's recipients", 0x0017)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeWrongGroupException, "Envelope was written for another group", 0x0018)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeWrongAuthorException, "Envelope was written by someone other than the expected author", 0x0019)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeUnverifiedAuthorException, "The UserVerifier does not accept the key the envelope was signed with for its author", 0x001A)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeAuthorNotMemberException, "The envelope's author is not a member of the group", 0x001B)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeStaleEpochException, "Envelope is not from the group's current epoch", 0x001C)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeAuthorNotStatedException, "A read must name the expected author or say that any author is accepted", 0x001D)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeSequenceOrderException, "Sequence item or mark is out of order, repeated, or does not match what was read", 0x001E)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, EnvelopeFileCorruptedException, "Encrypted file data is not what its envelope lists", 0x001F)
// clang-format on
} // namespace group
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_GROUP_EXT_EXCEPTION_HPP_
