/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/inbox/InboxProvider.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

InboxProvider::InboxProvider(std::function<server::Inbox(std::string)> getInbox, std::function<uint32_t(server::Inbox)> validateInbox)
     : core::ContainerProvider<std::string, server::Inbox>(getInbox, validateInbox) {}
    
bool InboxProvider::isNewerOrSameAsInStorage(const server::Inbox& container) {
    auto cached = _storage.get(container.id());
    if(!cached.has_value()) {
        return true;
    }
    auto cached_container = cached.value().container;
    if (container.version() > cached_container.version() ||
        (container.lastModificationDate() >= cached_container.lastModificationDate() && container.version() == cached_container.version())
    ) {
        return true;
    }
    return false;
}