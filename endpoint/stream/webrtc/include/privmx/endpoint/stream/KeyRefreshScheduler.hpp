/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_KEYREFRESHSCHEDULER_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_KEYREFRESHSCHEDULER_HPP_

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <privmx/utils/GuardedExecutor.hpp>

namespace privmx {
namespace endpoint {
namespace stream {

// Runs a Stream Room's key refresh away from the thread which asked for it, at most one at a time per
// Stream Room and no more often than the cooldown allows.
class KeyRefreshScheduler {
public:
    using RefreshHandler = std::function<void(const std::string& streamRoomId)>;

    KeyRefreshScheduler(RefreshHandler onRefreshNeeded, std::chrono::milliseconds cooldown = std::chrono::seconds(10));
    ~KeyRefreshScheduler();

    // safe to call from a WebRTC thread: it never blocks and never calls the handler inline
    void requestRefresh(const std::string& streamRoomId);
    void forgetRoom(const std::string& streamRoomId);

private:
    struct RoomState {
        bool refreshing{false};
        std::chrono::steady_clock::time_point refreshedAt{};
        bool everRefreshed{false};
    };

    void runRefresh(const std::string& streamRoomId);

    RefreshHandler _onRefreshNeeded;
    std::chrono::milliseconds _cooldown;
    std::mutex _mutex;
    std::unordered_map<std::string, RoomState> _rooms;
    // reset last, so every queued refresh is finished before the state it touches is gone
    std::shared_ptr<privmx::utils::GuardedExecutor> _executor;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_KEYREFRESHSCHEDULER_HPP_
