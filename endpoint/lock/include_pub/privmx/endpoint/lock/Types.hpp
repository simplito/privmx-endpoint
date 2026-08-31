/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_LOCK_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_LOCK_TYPES_HPP_

#include <cstdint>

namespace privmx {
namespace endpoint {
namespace lock {

/**
 * Lock level describing the type of lock held on a resource.
 */
enum LockLevel : int64_t {
    /** No lock held */
    NONE = 0,
    /** Shared (reader) lock — multiple holders allowed */
    SHARED = 1,
    /** Reserved lock — signals intent to escalate to exclusive */
    RESERVED = 2,
    /** Pending lock — waiting for readers to finish before escalating */
    PENDING = 3,
    /** Exclusive (writer) lock — single holder, no other locks allowed */
    EXCLUSIVE = 4,
};

/**
 * Result of a lock or unlock operation.
 */
struct LockOperationResult {
    /**
     * Whether the requested lock level was successfully acquired/released.
     */
    bool success;

    /**
     * The lock level currently held by the caller after the operation.
     */
    LockLevel currentLevel;
};

} // namespace lock
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_LOCK_TYPES_HPP_