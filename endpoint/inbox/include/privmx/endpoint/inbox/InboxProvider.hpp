/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_INBOX_INBOXCACHE_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_INBOXCACHE_HPP_

#include <privmx/endpoint/core/ContainerProvider.hpp>
#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include "privmx/endpoint/inbox/InboxException.hpp"

namespace privmx {
namespace endpoint {
namespace inbox {

class InboxProvider : public core::ContainerProvider<std::string, server::Inbox> {
public:
    InboxProvider(std::function<server::Inbox(std::string)> getThread);
    void updateByValue(const server::Inbox& value) override;
};

} // inbox
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_INBOX_INBOXCACHE_HPP_