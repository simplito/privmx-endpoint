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
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/UserVerifierInterface.hpp"

namespace privmx {
namespace endpoint {
namespace core {

// The verifier Connection::useKeyContinuity sets: trust on first use, then continuity. The first
// key a user of a Context is seen with is taken as theirs if it is the key the Bridge lists for that user in that
// Context (`listedKeys`, read fresh) and is not already pinned to another user there; any other key for that user is refused
// until the application accepts the change (`accept`, behind Connection::acceptKeyChange). A key replaced that way
// stays good for what was dated before the change was accepted, and for nothing after.
//
// SECURITY: the first key is never taken from the request alone. The request's key comes from what is being
// verified (a signed header names its own author and key), so anyone in the Context could otherwise sign as "ceo"
// with her own key and have it pinned as ceo's.
//
// It proves nothing about the first key beyond the Bridge's word: an application that can ask its own server or a
// PKI should set a UserVerifierInterface that does.
//
// ponytail: kept in memory for the connection's lifetime, so every new connection trusts first use again; seal the
// map into the PinStore next to the group pins when that matters.
class KeyContinuityVerifier : public virtual UserVerifierInterface {
public:
    // userId -> public key (Base58DER) of every user the Bridge lists in a Context.
    using ListedKeys = std::function<std::map<std::string, std::string>(const std::string& contextId)>;

    // `ownUserId`: this connection's user id in a Context, or "" when it cannot be told. Asked only for a request
    // that presents one of the connection's own keys.
    // `listedKeys`: asked once per `verify` call and Context with a first use in it, never cached across calls (a
    // pinned user is not asked about again). Null, or throwing: no first use is accepted.
    explicit KeyContinuityVerifier(
        std::function<std::string(const std::string& contextId)> ownUserId = nullptr,
        ListedKeys listedKeys = nullptr
    )
        : _ownUserId(std::move(ownUserId)), _listedKeys(std::move(listedKeys)) {}

    std::vector<bool> verify(const std::vector<VerificationRequest>& request) override {
        // Which requests present a key of this connection's own user, as that user: looked up outside the lock.
        // UNDECIDED goes through continuity below; the other two are the answer.
        enum class Own {
            UNDECIDED,
            YES,
            NO
        };
        std::vector<Own> own(request.size(), Own::UNDECIDED);
        for (std::size_t i = 0; i < request.size(); ++i) {
            const VerificationRequest& item = request[i];
            std::int64_t validUntil = 0;
            {
                std::lock_guard<std::mutex> lock(_mutex);
                const auto key = _own.find(item.senderPubKey);
                if (key == _own.end()) {
                    continue;
                }
                validUntil = key->second;
            }
            // SECURITY: an own key vouches for the own user only. Under any other user id it is a key like any
            // other, and goes through continuity below.
            std::string self;
            try {
                self = _ownUserId ? _ownUserId(item.contextId) : std::string();
            } catch (...) {}
            if (!self.empty() && self == item.senderId) {
                // The connection knows this key of its own user, and until when it was theirs: nothing to guess.
                own[i] = validUntil == CURRENT || item.date <= validUntil ? Own::YES : Own::NO;
            }
        }
        // What the Bridge lists for each user seen for the first time: looked up outside the lock, too.
        std::vector<bool> listed(request.size(), false);
        std::map<std::string, std::optional<std::map<std::string, std::string>>> listings; // this call's only
        for (std::size_t i = 0; i < request.size(); ++i) {
            const VerificationRequest& item = request[i];
            if (own[i] != Own::UNDECIDED || isPinned(item.contextId, item.senderId)) {
                continue;
            }
            listed[i] = isListed(item.contextId, item.senderId, item.senderPubKey, listings);
        }
        std::lock_guard<std::mutex> lock(_mutex);
        std::vector<bool> result;
        result.reserve(request.size());
        for (std::size_t i = 0; i < request.size(); ++i) {
            const VerificationRequest& item = request[i];
            if (own[i] != Own::UNDECIDED) {
                result.push_back(own[i] == Own::YES);
                continue;
            }
            std::vector<Known>& known = _keys[{item.contextId, item.senderId}];
            if (known.empty()) {
                // SECURITY: first use takes the Bridge's key for the user, never one pinned to another user.
                const bool ok = listed[i] && !pinnedToAnother(item.contextId, item.senderId, item.senderPubKey);
                if (ok) {
                    known.push_back(Known{item.senderPubKey, CURRENT});
                } else {
                    _keys.erase({item.contextId, item.senderId});
                }
                result.push_back(ok);
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

    // A key of this connection's own user: the one it connected with (`current`), or one it was told it had before
    // (Connection::adoptPreviousIdentity), which stays good for what is dated up to now, like a key replaced through
    // `accept`. Without this a user who changed key would be refused their own statements.
    void trustOwn(const std::string& pubKey, bool current) {
        const std::int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::system_clock::now().time_since_epoch()
        )
                                     .count();
        std::lock_guard<std::mutex> lock(_mutex);
        const auto known = _own.find(pubKey);
        if (current) {
            _own[pubKey] = CURRENT;
        } else if (known == _own.end()) {
            _own[pubKey] = now;
        }
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

    bool isPinned(const std::string& contextId, const std::string& userId) {
        std::lock_guard<std::mutex> lock(_mutex);
        const auto known = _keys.find({contextId, userId});
        return known != _keys.end() && !known->second.empty();
    }

    // Under _mutex.
    bool pinnedToAnother(const std::string& contextId, const std::string& userId, const std::string& pubKey) {
        for (auto it = _keys.lower_bound({contextId, ""}); it != _keys.end() && it->first.first == contextId; ++it) {
            if (it->first.second == userId) {
                continue;
            }
            for (const Known& key : it->second) {
                if (key.pubKey == pubKey) {
                    return true;
                }
            }
        }
        return false;
    }

    // Whether the Bridge lists `pubKey` for the user; false when it cannot be asked. Not under _mutex.
    // SECURITY: the listing is fetched fresh for each `verify` call that has a first use in the Context, never taken
    // from an earlier call: a key the user replaced (after a compromise, say) must not be pinned off a stale list.
    bool isListed(
        const std::string& contextId,
        const std::string& userId,
        const std::string& pubKey,
        std::map<std::string, std::optional<std::map<std::string, std::string>>>& listings
    ) {
        if (!_listedKeys) {
            return false;
        }
        auto listing = listings.find(contextId);
        if (listing == listings.end()) {
            std::optional<std::map<std::string, std::string>> users;
            try {
                users = _listedKeys(contextId);
            } catch (...) {}
            listing = listings.emplace(contextId, std::move(users)).first;
        }
        if (!listing->second.has_value()) {
            return false;
        }
        const auto user = listing->second->find(userId);
        return user != listing->second->end() && user->second == pubKey;
    }

    std::mutex _mutex;
    std::function<std::string(const std::string&)> _ownUserId;
    ListedKeys _listedKeys;
    std::map<std::string, std::int64_t> _own; // own public key -> CURRENT, or when it was adopted as a previous one
    std::map<std::pair<std::string, std::string>, std::vector<Known>> _keys; // (contextId, userId)
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_KEYCONTINUITYVERIFIER_HPP_
