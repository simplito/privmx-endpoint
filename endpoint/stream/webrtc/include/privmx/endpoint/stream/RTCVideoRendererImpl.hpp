/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_WEBRTC_RTC_VIDEO_RENDERER_IMPL_HPP_
#define _PRIVMXLIB_ENDPOINT_WEBRTC_RTC_VIDEO_RENDERER_IMPL_HPP_

#include <string>
#include <libwebrtc.h>
#include <rtc_video_frame.h>
#include "privmx/endpoint/stream/webrtc/Types.hpp"
#include "privmx/endpoint/stream/webrtc/OnTrackInterface.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>

namespace privmx {
namespace endpoint {
namespace stream {


class FrameImpl : public Frame {
public:
    FrameImpl(libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame> frame);
    virtual int ConvertToRGBA(uint8_t* dst_argb, int dst_stride_argb, int dest_width, int dest_height) override;
private:
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame> _frame;
};


class RTCVideoRendererImpl : public libwebrtc::RTCVideoRenderer<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>> {
public:
    RTCVideoRendererImpl(
        std::shared_ptr<OnTrackInterface> roomOnTrackInterface,
        std::shared_ptr<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>> streamOnTrackInterfacesMap, 
        const std::vector<std::string>& streamIds, 
        libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track
    );
    RTCVideoRendererImpl(const std::vector<std::string>& streamIds, libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track);
    ~RTCVideoRendererImpl();
    void updateRoomOnTrackInterface(std::shared_ptr<OnTrackInterface> roomOnTrackInterface);
    void updateStreamOnTrackInterfacesMap(std::shared_ptr<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>> streamOnTrackInterfacesMap);
    virtual void OnFrame(libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame> frame) override;
private:
    std::mutex m;
    std::shared_ptr<OnTrackInterface> _roomOnTrackInterface;
    std::shared_ptr<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>> _streamOnTrackInterfacesMap;
    std::vector<std::string> _streamIds;
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> _track;
};


} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_WEBRTC_RTC_VIDEO_RENDERER_IMPL_HPP_
