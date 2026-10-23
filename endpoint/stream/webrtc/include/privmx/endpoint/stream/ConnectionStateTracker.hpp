/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_CONNECTION_STATE_TRACKER_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_CONNECTION_STATE_TRACKER_HPP_

#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "privmx/endpoint/stream/webrtc/Types.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class ConnectionStateTracker {
public:
    // returns whether a recovery of this connection was started; a connection which cannot be recovered is
    // given up on at once and makes its Stream Room report StreamLost
    using RecoveryHandler = std::function<bool(const std::string& streamRoomId, const std::string& connectionType)>;
    using StateHandler = std::function<void(const std::string& streamRoomId, StreamConnectionState state)>;

    ConnectionStateTracker(
        StateHandler onStateChanged,
        RecoveryHandler onRecoveryNeeded,
        std::chrono::milliseconds gracePeriod = std::chrono::seconds(2),
        int maxRecoveryAttempts = 3
    );
    ~ConnectionStateTracker();
    ConnectionStateTracker(const ConnectionStateTracker&) = delete;
    ConnectionStateTracker& operator=(const ConnectionStateTracker&) = delete;

    void setConnectionState(
        const std::string& streamRoomId,
        const std::string& connectionType,
        PeerConnectionState state
    );
    void forgetRoom(const std::string& streamRoomId);

private:
    struct ConnectionEntry {
        PeerConnectionState state{PeerConnectionNew};
        int recoveryAttempts{0};
        bool givenUp{false};
        // when the connection stops being given the benefit of the doubt: a recovery is started then and the
        // Stream Room's state is reported then
        std::optional<std::chrono::steady_clock::time_point> actAt;
    };

    struct RoomState {
        std::map<std::string, ConnectionEntry> connections;
        std::optional<StreamConnectionState> reported;
    };

    struct Recovery {
        std::string streamRoomId;
        std::string connectionType;
    };

    static bool isBroken(PeerConnectionState state);

    // a broken connection whose first recovery has not started yet is left out, so one flapping through
    // disconnected does not change what the Stream Room reports
    static std::optional<StreamConnectionState> aggregate(
        const RoomState& room,
        std::chrono::steady_clock::time_point now
    );

    std::optional<StreamConnectionState> evaluate(RoomState& room);
    void collectDueRecoveries(const std::string& streamRoomId, RoomState& room, std::vector<Recovery>& due);
    std::optional<std::chrono::steady_clock::time_point> earliestDeadline() const;
    void runRecoveries(const std::vector<Recovery>& due);
    void run();

    StateHandler _onStateChanged;
    RecoveryHandler _onRecoveryNeeded;
    std::chrono::milliseconds _gracePeriod;
    int _maxRecoveryAttempts;
    mutable std::mutex _mutex;
    std::condition_variable _wakeUp;
    bool _stopping;
    std::map<std::string, RoomState> _rooms;
    std::thread _worker;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_CONNECTION_STATE_TRACKER_HPP_
