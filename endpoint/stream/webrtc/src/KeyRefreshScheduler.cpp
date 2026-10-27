/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/KeyRefreshScheduler.hpp"

#include <utility>

#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::stream;

KeyRefreshScheduler::KeyRefreshScheduler(RefreshHandler onRefreshNeeded, std::chrono::milliseconds cooldown)
    : _onRefreshNeeded(std::move(onRefreshNeeded)), _cooldown(cooldown),
      _executor(std::make_shared<privmx::utils::GuardedExecutor>()) {}

KeyRefreshScheduler::~KeyRefreshScheduler() {
    // waits for the queued refreshes, so none of them outlives the state it reports back into
    _executor.reset();
}

void KeyRefreshScheduler::requestRefresh(const std::string& streamRoomId) {
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto& room = _rooms[streamRoomId];
        if (room.refreshing) {
            return;
        }
        // a key the user will never be granted keeps failing to decrypt, so without this the Stream Room
        // would ask the Bridge for its keys again for as long as it stays open
        if (room.everRefreshed && std::chrono::steady_clock::now() - room.refreshedAt < _cooldown) {
            return;
        }
        room.refreshing = true;
    }
    _executor->exec([this, streamRoomId]() { runRefresh(streamRoomId); });
}

void KeyRefreshScheduler::forgetRoom(const std::string& streamRoomId) {
    std::lock_guard<std::mutex> lock(_mutex);
    _rooms.erase(streamRoomId);
}

void KeyRefreshScheduler::runRefresh(const std::string& streamRoomId) {
    try {
        _onRefreshNeeded(streamRoomId);
    } catch (...) { LOG_ERROR("KeyRefreshScheduler::runRefresh", "refreshing the Stream Room keys failed") }
    std::lock_guard<std::mutex> lock(_mutex);
    auto room = _rooms.find(streamRoomId);
    if (room == _rooms.end()) {
        return;
    }
    room->second.refreshing = false;
    room->second.refreshedAt = std::chrono::steady_clock::now();
    room->second.everRefreshed = true;
}
