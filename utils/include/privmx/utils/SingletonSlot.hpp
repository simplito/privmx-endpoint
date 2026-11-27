/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_SINGLETONSLOT_HPP_
#define _PRIVMXLIB_UTILS_SINGLETONSLOT_HPP_

#include <memory>

namespace privmx {
namespace utils {

/**
 * @brief A slot for a singleton instance that `SingletonsHolder` also holds.
 *
 * **The problem it solves.** Each of these singletons has two owners: its own static handle, and
 * `SingletonsHolder`, which calls `freeInstance()` in a fixed order at shutdown. The destruction
 * order of statics across translation units is **unspecified**, so the static handle may be gone
 * before `SingletonsHolder`'s destructor runs — and `freeInstance()` then reaches into freed
 * memory. This happened for real: after `PublicKeyCache` moved into
 * `libprivmxendpointcore.so`, the same library as `SingletonsHolder`, ASAN reported a
 * use-after-free at program exit. The previous library layout had been masking the bug by accident.
 *
 * **How it works.** The `alive()` marker is a plain `bool`: constant-initialised and without a
 * destructor, so it can be read for the whole lifetime of the program — including after the slot
 * itself is gone. `freeInstance()` checks it before touching the slot.
 *
 * **What it does not break.** The slot still destroys itself, so a program that does not use
 * `SingletonsHolder` (the `utils` unit tests, for one) still cleans up at exit — which matters for
 * `Executor`, whose destructor stops the thread pool. And where `SingletonsHolder` does exist, it
 * holds the last reference, so the actual destruction order of the objects remains the one its
 * destructor imposes.
 *
 * **Limitation.** `ref()` may only be called from a live program, not during static destruction.
 * No `getInstance()` is called at that stage.
 */
template <typename T>
class SingletonSlot {
public:
    /// Whether the slot still exists. Always safe to read, including after it has been destroyed.
    static bool alive() { return _alive; }

    std::shared_ptr<T>& ref() { return _ptr; }

    ~SingletonSlot() { _alive = false; }

private:
    std::shared_ptr<T> _ptr;
    static inline bool _alive = true;
};

} // namespace utils
} // namespace privmx

#endif // _PRIVMXLIB_UTILS_SINGLETONSLOT_HPP_
