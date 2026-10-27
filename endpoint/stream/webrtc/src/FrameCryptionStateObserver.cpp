/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/FrameCryptionStateObserver.hpp"

#include <utility>

#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::stream;

FrameCryptionStateObserver::FrameCryptionStateObserver(MissingKeyHandler onMissingKey)
    : _onMissingKey(std::move(onMissingKey)) {}

void FrameCryptionStateObserver::onFrameCryptionStateChanged(privmx::webrtc::FrameCryptionState state) {
    if (state != privmx::webrtc::FrameCryptionState::MissingKey || !_onMissingKey) {
        return;
    }
    try {
        _onMissingKey();
    } catch (...) {
        LOG_ERROR("FrameCryptionStateObserver::onFrameCryptionStateChanged", "reporting the missing key failed")
    }
}
