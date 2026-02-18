#ifndef _PRIVMXLIB_ENDPOINT_GROUP_EXT_EXCEPTION_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_EXT_EXCEPTION_HPP_


#include "privmx/endpoint/core/Exception.hpp"

#define DECLARE_SCOPE_ENDPOINT_EXCEPTION(NAME, MSG, SCOPE, CODE, ...)                                            \
    class NAME : public privmx::endpoint::core::Exception {                                                      \
    public:                                                                                                      \
        NAME() : privmx::endpoint::core::Exception(MSG, #NAME, SCOPE, (CODE << 16)) {}                           \
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
namespace group {

#define ENDPOINT_GROUP_EXCEPTION_CODE 0x000D0000

DECLARE_SCOPE_ENDPOINT_EXCEPTION(EndpointGroupException, "Unknown endpoint group exception", "Group", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, NotInitializedException, "Endpoint not initialized", 0x0001)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, CannotExtractGroupCreatedEventException, "Cannot extract GroupCreatedEvent", 0x0002)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, CannotExtractGroupUpdatedEventException, "Cannot extract GroupUpdatedEvent", 0x0003)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, CannotExtractGroupNewMessageEventException, "Cannot extract GroupNewMessageEvent", 0x0004)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, CannotExtractGroupDeletedEventException, "Cannot extract GroupDeletedEvent", 0x0005)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, CannotExtractGroupDeletedMessageEventException, "Cannot extract GroupDeletedMessageEvent", 0x0006)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, IncorrectKeyIdFormatException, "Incorrect key id format", 0x0007)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, CannotExtractGroupStatsEventException, "Cannot extract GroupStatsEvent", 0x0008)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, AlreadySubscribedException, "Already subscribed", 0x0009)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, NotSubscribedException, "Cannot unsubscribe if not subscribed", 0x000A)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, InvalidEncryptedGroupDataVersionException, "Invalid version of encrypted group data", 0x000B)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, InvalidEncryptedMessageDataVersionException, "Invalid version of encrypted message data", 0x000C)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, UnknowGroupFormatException, "Unknown Group format", 0x000D)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, UnknowMessageFormatException, "Unknown Message format", 0x000E)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, CannotExtractGroupMessageUpdatedEventException, "Cannot extract GroupMessageUpdatedEvent", 0x000F)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupPublicDataMismatchException, "Group public data mismatch", 0x0010)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, MessagePublicDataMismatchException, "Message public data mismatch", 0x0011)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupDataIntegrityException, "Failed group data integrity check", 0x0014)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, MessageDataIntegrityException, "Failed message data integrity check", 0x0015)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, GroupEncryptionKeyValidationException, "Failed Group encryption key validation", 0x0016)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, NotImplementedException, "Not Implemented", 0x0017)
DECLARE_ENDPOINT_EXCEPTION(EndpointGroupException, InvalidSubscriptionQueryException, "Invalid subscriptionQuery", 0x0018)

} // group
} // endpoint
} // privmx

#undef DECLARE_SCOPE_ENDPOINT_EXCEPTION
#undef DECLARE_ENDPOINT_EXCEPTION

#endif // _PRIVMXLIB_ENDPOINT_GROUP_EXT_EXCEPTION_HPP_