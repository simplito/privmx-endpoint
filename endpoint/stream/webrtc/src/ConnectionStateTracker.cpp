/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/ConnectionStateTracker.hpp"

#include <utility>

using namespace privmx::endpoint::stream;

ConnectionStateTracker::ConnectionStateTracker(
    StateHandler onStateChanged,
    RecoveryHandler onRecoveryNeeded,
    std::chrono::milliseconds gracePeriod,
    int maxRecoveryAttempts
)
    : _onStateChanged(std::move(onStateChanged)), _onRecoveryNeeded(std::move(onRecoveryNeeded)),
      _gracePeriod(gracePeriod), _maxRecoveryAttempts(maxRecoveryAttempts), _stopping(false), _workPending(false) {
    _worker = std::thread(&ConnectionStateTracker::run, this);
}

ConnectionStateTracker::~ConnectionStateTracker() {
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _stopping = true;
    }
    _wakeUp.notify_all();
    if (_worker.joinable()) {
        _worker.join();
    }
}

bool ConnectionStateTracker::isBroken(PeerConnectionState state) {
    return state == PeerConnectionDisconnected || state == PeerConnectionFailed;
}

void ConnectionStateTracker::setConnectionState(
    const std::string& streamRoomId,
    const std::string& connectionType,
    PeerConnectionState state
) {
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto& room = _rooms[streamRoomId];
        if (state == PeerConnectionClosed) {
            room.connections.erase(connectionType);
        } else {
            auto& connection = room.connections[connectionType];
            connection.state = state;
            if (state == PeerConnectionConnected) {
                connection.recoveryAttempts = 0;
                connection.givenUp = false;
                connection.actAt = std::nullopt;
            } else if (isBroken(state) && !connection.givenUp && !connection.actAt.has_value()) {
                // a failed connection will not come back by itself, so it is acted on at once, while a
                // disconnected one is given the grace period to recover on its own
                connection.actAt = std::chrono::steady_clock::now() +
                    (state == PeerConnectionFailed ? std::chrono::milliseconds(0) : _gracePeriod);
            }
        }
        if (room.connections.empty()) {
            _rooms.erase(streamRoomId);
        }
        _workPending = true;
    }
    // Reporting a state only records it. Deciding and recovering happen on the worker, so a recovery
    // never runs on the thread which reported the state - that thread is usually the WebRTC layer's own,
    // and a recovery calls straight back into it.
    _wakeUp.notify_all();
}

void ConnectionStateTracker::forgetRoom(const std::string& streamRoomId) {
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _rooms.erase(streamRoomId);
        _workPending = true;
    }
    _wakeUp.notify_all();
}

std::optional<StreamConnectionState> ConnectionStateTracker::aggregate(
    const RoomState& room,
    std::chrono::steady_clock::time_point now
) {
    bool anyTracked = false;
    bool anyGivenUp = false;
    bool anyBroken = false;
    bool allConnected = true;
    for (const auto& entry : room.connections) {
        const auto& connection = entry.second;
        if (connection.state == PeerConnectionNew) {
            continue;
        }
        // before the first recovery attempt a broken connection is still given its grace period; once one
        // has been started the Stream Room is reported as reconnecting until the connection comes back
        if (isBroken(connection.state) &&
            connection.recoveryAttempts == 0 &&
            connection.actAt.has_value() &&
            now < connection.actAt.value()) {
            continue;
        }
        anyTracked = true;
        if (connection.givenUp) {
            anyGivenUp = true;
        }
        if (isBroken(connection.state)) {
            anyBroken = true;
        }
        if (connection.state != PeerConnectionConnected) {
            allConnected = false;
        }
    }
    if (!anyTracked) {
        return std::nullopt;
    }
    if (anyGivenUp) {
        return StreamLost;
    }
    if (anyBroken) {
        return StreamReconnecting;
    }
    if (allConnected) {
        return StreamConnected;
    }
    return std::nullopt;
}

void ConnectionStateTracker::collectDueRecoveries(
    const std::string& streamRoomId,
    RoomState& room,
    std::vector<Recovery>& due
) {
    const auto now = std::chrono::steady_clock::now();
    for (auto& entry : room.connections) {
        auto& connection = entry.second;
        if (!connection.actAt.has_value() || now < connection.actAt.value() || connection.givenUp) {
            continue;
        }
        if (connection.recoveryAttempts >= _maxRecoveryAttempts) {
            connection.givenUp = true;
            connection.actAt = std::nullopt;
            continue;
        }
        connection.recoveryAttempts++;
        // the next attempt waits out a grace period, which also bounds how often a broken connection retries
        connection.actAt = now + _gracePeriod;
        due.push_back({streamRoomId, entry.first});
    }
}

std::optional<StreamConnectionState> ConnectionStateTracker::evaluate(RoomState& room) {
    auto desired = aggregate(room, std::chrono::steady_clock::now());
    if (!desired.has_value() || (room.reported.has_value() && room.reported.value() == desired.value())) {
        return std::nullopt;
    }
    room.reported = desired;
    return desired;
}

std::optional<std::chrono::steady_clock::time_point> ConnectionStateTracker::earliestDeadline() const {
    std::optional<std::chrono::steady_clock::time_point> earliest;
    for (const auto& room : _rooms) {
        for (const auto& entry : room.second.connections) {
            const auto& actAt = entry.second.actAt;
            if (actAt.has_value() && (!earliest.has_value() || actAt.value() < earliest.value())) {
                earliest = actAt;
            }
        }
    }
    return earliest;
}

void ConnectionStateTracker::runRecoveries(const std::vector<Recovery>& due) {
    for (const auto& recovery : due) {
        bool started = false;
        try {
            started = _onRecoveryNeeded(recovery.streamRoomId, recovery.connectionType);
        } catch (...) { started = false; }
        if (started) {
            continue;
        }
        std::lock_guard<std::mutex> lock(_mutex);
        auto room = _rooms.find(recovery.streamRoomId);
        if (room == _rooms.end()) {
            continue;
        }
        auto connection = room->second.connections.find(recovery.connectionType);
        if (connection == room->second.connections.end()) {
            continue;
        }
        connection->second.givenUp = true;
        connection->second.actAt = std::nullopt;
    }
}

void ConnectionStateTracker::run() {
    std::unique_lock<std::mutex> lock(_mutex);
    while (!_stopping) {
        auto deadline = earliestDeadline();
        auto hasWork = [this]() { return _stopping || _workPending; };
        if (deadline.has_value()) {
            _wakeUp.wait_until(lock, deadline.value(), hasWork);
        } else {
            _wakeUp.wait(lock, hasWork);
        }
        if (_stopping) {
            return;
        }
        _workPending = false;
        std::vector<Recovery> due;
        for (auto& room : _rooms) {
            collectDueRecoveries(room.first, room.second, due);
        }
        // both handlers reach the application, so neither may run under the lock
        lock.unlock();
        runRecoveries(due);
        lock.lock();
        std::vector<std::pair<std::string, StreamConnectionState>> emissions;
        for (auto& room : _rooms) {
            auto toEmit = evaluate(room.second);
            if (toEmit.has_value()) {
                emissions.push_back({room.first, toEmit.value()});
            }
        }
        if (emissions.empty()) {
            continue;
        }
        lock.unlock();
        for (const auto& emission : emissions) {
            _onStateChanged(emission.first, emission.second);
        }
        lock.lock();
    }
}
