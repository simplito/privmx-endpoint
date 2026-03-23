#ifndef _PRIVMXLIB_ENDPOINT_STREAM_DATA_CHANEL_IMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_DATA_CHANEL_IMPL_HPP_

#include <string>
#include <libwebrtc.h>
#include <rtc_peerconnection.h>
#include "privmx/endpoint/stream/webrtc/Types.hpp"
#include "privmx/endpoint/stream/webrtc/OnTrackInterface.hpp"
#include "privmx/endpoint/stream/PmxDataChannelObserver.hpp"
#include <privmx/utils/Logger.hpp>

namespace privmx {
namespace endpoint {
namespace stream {


class DataChannelImpl {
public:
    inline DataChannelImpl(std::shared_ptr<OnTrackInterface> onTrackInterface, libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> dataChannel) :
        _onTrackInterface(onTrackInterface), 
        _dataChannel(dataChannel), 
        _dataChannelObserver(std::make_shared<PmxDataChannelObserver>(
            onTrackInterface, dataChannel->label().std_string()+":"+std::to_string(dataChannel->id())
        )) 
    {
        _dataChannel->RegisterObserver(_dataChannelObserver.get());
        LOG_TRACE("DataChannelImpl created")
    }
    inline ~DataChannelImpl() {
        LOG_TRACE("DataChannelImpl destroyed")
    }
    void updateOnTrackInterface(std::shared_ptr<OnTrackInterface> onTrackInterface) {
        std::unique_lock<std::mutex> lock(m);
        _onTrackInterface = onTrackInterface;
    }
private:
    std::mutex m;
    std::shared_ptr<OnTrackInterface> _onTrackInterface;
    libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> _dataChannel;
    std::shared_ptr<PmxDataChannelObserver> _dataChannelObserver;

};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_DATA_CHANEL_IMPL_HPP_