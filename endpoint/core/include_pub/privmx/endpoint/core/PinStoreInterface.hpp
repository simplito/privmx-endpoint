/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _PRIVMXLIB_ENDPOINT_CORE_PINSTOREINTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_PINSTOREINTERFACE_HPP_

#include <string>

#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

/**
 * Where the library keeps state between sessions: the key-tree pins of every group this device verified. With a
 * store, a group this device has verified once is never again read on trust (TOFU), across restarts of one identity
 * on one Bridge. Instances running side by side (tabs, processes) load the slot when created and merge with it at
 * every save: per group the higher commit wins.
 *
 * The store must be local to the device and not writable by the Bridge. The library seals what it saves (an HMAC
 * under a key derived from the identity key, bound to the slot's key): a changed blob is ignored, a deleted one
 * weakens protection back to first contact and an older one back to the older state it holds. A store the Bridge
 * hosts gives the Bridge exactly those two levers.
 *
 * `save` must be atomic against concurrent writers of the same key (other tabs, processes, GroupApis): it writes
 * `blob` only if the stored value still equals `expected` (empty = nothing stored) and returns whether it did. In a
 * browser an IndexedDB readwrite transaction does this; a file store compares and renames under a lock.
 *
 * Threading: both callbacks may run on any library thread, including the background worker, while a library lock (a
 * per-group commit lock, the pin-save lock) is held. They must be synchronous and must not call back into the
 * endpoint. A store with a small quota (localStorage, ~5 MiB) is unsupported: a failed save is logged and retried, and
 * until one succeeds the pins live in memory only, as without a store.
 */
class PinStoreInterface {
public:
    /**
     * @param key the slot, e.g. "group-pins/<scope>/<public key>"
     * @return the stored blob, empty if nothing is stored
     */
    virtual Buffer load(const std::string& key) = 0;
    /**
     * Compare-and-swap: stores `blob` only if the stored value equals `expected` (empty = nothing stored).
     * @return whether `blob` was stored
     */
    virtual bool save(const std::string& key, const Buffer& blob, const Buffer& expected) = 0;

protected:
    virtual ~PinStoreInterface() = default;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_PINSTOREINTERFACE_HPP_
