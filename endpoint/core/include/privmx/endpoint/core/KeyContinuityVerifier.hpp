/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_KEYCONTINUITYVERIFIER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_KEYCONTINUITYVERIFIER_HPP_

#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/UserVerifierInterface.hpp"

namespace privmx {
namespace endpoint {
namespace core {

// The verifier a connection has until the application sets its own: trust on first use, then continuity. The first
// key a user of a Context is seen with is taken as theirs; any other key for that user is refused until the
// application accepts the change (`accept`, behind Connection::acceptKeyChange). A key replaced that way stays good
// for what was dated before the change was accepted, and for nothing after.
//
// It proves nothing about the first key: an application that can ask its own server or a PKI should set a
// UserVerifierInterface that does.
//
// ponytail: kept in memory for the connection's lifetime, so every new connection trusts first use again; seal the
// map into the PinStore next to the group pins when that matters.
class KeyContinuityVerifier : public virtual UserVerifierInterface {
public:
    std::vector<bool> verify(const std::vector<VerificationRequest>& request) override {
        std::lock_guard<std::mutex> lock(_mutex);
        std::vector<bool> result;
        result.reserve(request.size());
        for (const VerificationRequest& item : request) {
            if (_own.count(item.senderPubKey) != 0) {
                result.push_back(true);
                continue;
            }
            std::vector<Known>& known = _keys[{item.contextId, item.senderId}];
            if (known.empty()) {
                known.push_back(Known{item.senderPubKey, CURRENT});
                result.push_back(true);
                continue;
            }
            bool ok = false;
            for (const Known& key : known) {
                if (key.pubKey == item.senderPubKey) {
                    ok = key.validUntil == CURRENT || item.date <= key.validUntil;
                }
            }
            result.push_back(ok);
        }
        return result;
    }

    // A key of this connection's own user: the one it connected with, or one it was told it had before
    // (Connection::adoptPreviousIdentity). Whatever is signed with it is the user's own, so continuity has nothing to
    // say about it: without this a user who changed key would be refused their own statements.
    void trustOwn(const std::string& pubKey) {
        std::lock_guard<std::mutex> lock(_mutex);
        _own.insert(pubKey);
    }

    // `newPubKey` becomes the user's key; `previousPubKey` stays good for what is dated up to now. Throws
    // InvalidParamsException when `previousPubKey` is not the key this verifier knows the user by: the caller is
    // then looking at another change than the one it means to accept.
    void accept(
        const std::string& contextId,
        const std::string& userId,
        const std::string& previousPubKey,
        const std::string& newPubKey
    ) {
        if (previousPubKey == newPubKey) {
            throw InvalidParamsException("the new key is the previous key");
        }
        const std::int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::system_clock::now().time_since_epoch()
        )
                                     .count();
        std::lock_guard<std::mutex> lock(_mutex);
        std::vector<Known>& known = _keys[{contextId, userId}];
        for (const Known& key : known) {
            if (key.validUntil == CURRENT && key.pubKey != previousPubKey) {
                throw InvalidParamsException("previousPubKey is not the key this client knows the user by");
            }
        }
        bool retired = false;
        for (Known& key : known) {
            if (key.pubKey == previousPubKey) {
                key.validUntil = now;
                retired = true;
            }
        }
        if (!retired) {
            known.push_back(Known{previousPubKey, now}); // a user not seen yet: both keys are the caller's word
        }
        for (Known& key : known) {
            if (key.pubKey == newPubKey) {
                key.validUntil = CURRENT;
                return;
            }
        }
        known.push_back(Known{newPubKey, CURRENT});
    }

private:
    static constexpr std::int64_t CURRENT = -1;
    struct Known {
        std::string pubKey;
        std::int64_t validUntil; // CURRENT, or the time its replacement was accepted (ms)
    };

    std::mutex _mutex;
    std::set<std::string> _own;
    std::map<std::pair<std::string, std::string>, std::vector<Known>> _keys; // (contextId, userId)
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_KEYCONTINUITYVERIFIER_HPP_
