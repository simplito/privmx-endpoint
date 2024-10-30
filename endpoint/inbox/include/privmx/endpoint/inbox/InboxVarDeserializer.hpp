#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXVARDESERIALIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXVARDESERIALIZER_HPP_

#include <Poco/Dynamic/Var.h>

#include <privmx/endpoint/core/VarDeserializer.hpp>
#include <string>

#include "privmx/endpoint/inbox/Events.hpp"
#include "privmx/endpoint/inbox/InboxApi.hpp"
#include "privmx/endpoint/inbox/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
inbox::FilesConfig VarDeserializer::deserialize<inbox::FilesConfig>(const Poco::Dynamic::Var& val,
                                                                    const std::string& name);

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_INBOX_INBOXVARDESERIALIZER_HPP_
