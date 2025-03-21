/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/ContextProvider.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

ContextProvider::ContextProvider(std::function<server::ContextInfo(std::string)> getContext) : core::ContainerProvider<std::string, server::ContextInfo>(getContext) {}
    
void ContextProvider::updateByValue(const server::ContextInfo& container) {
    auto cached = _storage.get(container.contextId());
    if(!cached.has_value()) {
        _storage.set(container.contextId(), container);
        return;
    }
    _storage.set(container.contextId(), container);
}