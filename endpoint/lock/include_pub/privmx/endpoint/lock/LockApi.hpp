/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_LOCK_LOCKAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_LOCK_LOCKAPI_HPP_

#include <string>

#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/lock/Types.hpp"
#include <privmx/endpoint/core/ExtendedPointer.hpp>

namespace privmx {
namespace endpoint {
namespace lock {

class LockApiImpl;

/**
 * 'LockApi' provides distributed locking of arbitrary resources identified by a string ID.
 * Lock levels follow the SQLite locking model: NONE < SHARED < RESERVED < PENDING < EXCLUSIVE.
 */
class LockApi : public privmx::endpoint::core::ExtendedPointer<LockApiImpl> {
public:
    /**
     * Creates an instance of 'LockApi'.
     *
     * @param connection instance of 'Connection'
     * @return LockApi object
     */
    static LockApi create(core::Connection& connection);

    /**
     * //doc-gen:ignore
     */
    LockApi();
    LockApi(const LockApi& obj);
    LockApi& operator=(const LockApi& obj);
    LockApi(LockApi&& obj);
    ~LockApi();

    /**
     * Attempts to acquire a lock on a resource at the requested level.
     *
     * @param resourceId identifier of the resource to lock
     * @param uuid caller-unique identifier used to track lock ownership
     * @param lockLevel desired lock level (SHARED, RESERVED, PENDING, or EXCLUSIVE)
     * @return result indicating success and the current lock level held by the caller
     */
    LockOperationResult lock(const std::string& resourceId, const std::string& uuid, LockLevel lockLevel);

    /**
     * Releases or downgrades a lock held on a resource.
     *
     * @param resourceId identifier of the resource to unlock
     * @param uuid caller-unique identifier matching the one used during lock acquisition
     * @param lockLevel target level to downgrade to (NONE releases fully, SHARED keeps a reader lock)
     * @return result indicating success and the current lock level held by the caller
     */
    LockOperationResult unlock(const std::string& resourceId, const std::string& uuid, LockLevel lockLevel);

    /**
     * Checks whether any connection (including the caller) holds a RESERVED or higher lock on the resource.
     *
     * @param resourceId identifier of the resource to check
     * @param uuid caller-unique identifier
     * @return true if a RESERVED or higher lock exists, false otherwise
     */
    bool checkReservedLock(const std::string& resourceId, const std::string& uuid);

private:
    LockApi(const std::shared_ptr<LockApiImpl>& impl);
};

} // namespace lock
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_LOCK_LOCKAPI_HPP_
