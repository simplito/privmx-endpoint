/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_PMX_DATA_CHANNEL_OBSERVER_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_PMX_DATA_CHANNEL_OBSERVER_HPP_

#include <string>
#include <libwebrtc.h>
#include <rtc_data_channel.h>
#include "privmx/endpoint/stream/webrtc/Types.hpp"
#include "privmx/endpoint/stream/webrtc/OnTrackInterface.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/utils/Logger.hpp>

namespace privmx {
namespace endpoint {
namespace stream {

class PmxDataChannelObserver : public libwebrtc::RTCDataChannelObserver {
public:
    PmxDataChannelObserver(std::shared_ptr<OnTrackInterface> onTrackInterface, const std::string& dataChannelId);
    virtual void OnStateChange(libwebrtc::RTCDataChannelState state) override;
    virtual void OnMessage(const char* buffer, int length, bool binary) override;
    void updateOnTrackInterface(std::shared_ptr<OnTrackInterface> onTrackInterface);
private:
    std::mutex _onTrackInterfaceMutex;
    std::shared_ptr<OnTrackInterface> _onTrackInterface;
    std::string _dataChannelId;
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_PMX_DATA_CHANNEL_OBSERVER_HPP_
