/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_LOCK_SERVERTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_LOCK_SERVERTYPES_HPP_

#include <string>

#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace lock {
namespace server {

#define LOCK_LOCK_MODEL_FIELDS(F)                                                                                      \
    F(resourceId, std::string)                                                                                         \
    F(uuid, std::string)                                                                                               \
    F(lockLevel, std::string)
JSON_STRUCT(LockLockModel, LOCK_LOCK_MODEL_FIELDS);

#define LOCK_UNLOCK_MODEL_FIELDS(F)                                                                                    \
    F(resourceId, std::string)                                                                                         \
    F(uuid, std::string)                                                                                               \
    F(lockLevel, std::string)
JSON_STRUCT(LockUnlockModel, LOCK_UNLOCK_MODEL_FIELDS);

// success: bool, currentLevel: string ("none"|"shared"|"reserved"|"pending"|"exclusive")
#define LOCK_OPERATION_RESULT_FIELDS(F)                                                                                \
    F(success, bool)                                                                                                   \
    F(currentLevel, std::string)
JSON_STRUCT(LockOperationResult, LOCK_OPERATION_RESULT_FIELDS);

#define LOCK_CHECK_RESERVED_LOCK_MODEL_FIELDS(F)                                                                       \
    F(resourceId, std::string)                                                                                         \
    F(uuid, std::string)
JSON_STRUCT(LockCheckReservedLockModel, LOCK_CHECK_RESERVED_LOCK_MODEL_FIELDS);

#define LOCK_CHECK_RESERVED_LOCK_RESULT_FIELDS(F) F(reserved, bool)
JSON_STRUCT(LockCheckReservedLockResult, LOCK_CHECK_RESERVED_LOCK_RESULT_FIELDS);

} // namespace server
} // namespace lock
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_LOCK_SERVERTYPES_HPP_
