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

ContextProvider::ContextProvider(std::function<server::ContextInfo(std::string)> getContext) 
    : core::ContainerProvider<std::string, server::ContextInfo>(getContext, []([[maybe_unused]]server::ContextInfo c) {return 0;}) {}

bool ContextProvider::isNewerOrSameAsInStorage([[maybe_unused]] const server::ContextInfo& container) {
    return true;
    // in current version of context is differentiate between newer context and older 
}