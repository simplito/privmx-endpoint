#ifndef _PRIVMXLIB_ENDPOINT_GROUP_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_EXT_EXCEPTION_HPP_

#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                                  \
    class NAME : public privmx::endpoint::core::Exception {                                                            \
    public:                                                                                                            \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                                 \
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
        NAME() : BASE_SCOPED(MSG, #NAME, CODE) {}                                                                      \
        NAME(const std::string& new_of_description) : BASE_SCOPED(MSG, #NAME, CODE, new_of_description) {}             \
        void rethrow() const override;                                                                                 \
    };                                                                                                                 \
    inline void NAME::rethrow() const {                                                                                \
        throw *this;                                                                                                   \
    };

namespace privmx {
namespace endpoint {
namespace group {
// clang-format off
#define ENDPOINT_GROUP_EXCEPTION_CODE 0x000B0000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointGroupException, "Unknown endpoint group exception", "Group", 0x000B)
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
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupChainBrokenException, "Group version chain link broken (G1)", 0x000B)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupUnauthorizedSignerException, "Group version signer was not an authorized manager (G2)", 0x000C)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupMembershipMismatchException, "Group membership in signed data does not match bridge-served fields", 0x000D)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, InvalidSubscriptionQueryException, "Invalid subscriptionQuery", 0x000E)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, RotatedAlreadyException, "Concurrent group key rotation: another manager won and one auto-retry did not resolve it", 0x000F)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupHistoryForkException, "Group history diverged from a previously verified state (version or keyVersion regressed)", 0x0010)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, IncompleteEpochLadderException, "Rotation aborted: the epoch ladder rung set for the new epoch would be incomplete", 0x0011)
// clang-format on
} // namespace group
} // namespace endpoint
} // namespace privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_GROUP_EXT_EXCEPTION_HPP_
