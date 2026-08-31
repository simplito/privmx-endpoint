/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/lock/VarSerializer.hpp"

#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

namespace {

const char* lockLevelToString(lock::LockLevel level) {
    switch (level) {
    case lock::LockLevel::NONE:
        return "none";
    case lock::LockLevel::SHARED:
        return "shared";
    case lock::LockLevel::RESERVED:
        return "reserved";
    case lock::LockLevel::PENDING:
        return "pending";
    case lock::LockLevel::EXCLUSIVE:
        return "exclusive";
    }
    return "none";
}

} // namespace

template<>
Poco::Dynamic::Var VarSerializer::serialize<lock::LockOperationResult>(const lock::LockOperationResult& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "lock$LockOperationResult");
    }
    obj->set("success", serialize(val.success));
    obj->set("currentLevel", serialize(static_cast<int64_t>(val.currentLevel)));
    obj->set("currentLevelName", std::string(lockLevelToString(val.currentLevel)));
    return obj;
}
