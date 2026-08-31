/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/lock/VarDeserializer.hpp"

#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
lock::LockLevel VarDeserializer::deserialize<lock::LockLevel>(const Poco::Dynamic::Var& val, const std::string& name) {
    switch (val.convert<int64_t>()) {
    case lock::LockLevel::NONE:
        return lock::LockLevel::NONE;
    case lock::LockLevel::SHARED:
        return lock::LockLevel::SHARED;
    case lock::LockLevel::RESERVED:
        return lock::LockLevel::RESERVED;
    case lock::LockLevel::PENDING:
        return lock::LockLevel::PENDING;
    case lock::LockLevel::EXCLUSIVE:
        return lock::LockLevel::EXCLUSIVE;
    }
    throw InvalidParamsException(
        name + " | " + ("Unknown lock::LockLevel value, received " + std::to_string(val.convert<int64_t>()))
    );
}
