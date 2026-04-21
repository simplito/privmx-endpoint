/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/RTCVideoRendererImpl.hpp"
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::stream; 

FrameImpl::FrameImpl(libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame> frame) : _frame(frame) {}

int FrameImpl::ConvertToRGBA(uint8_t* dst_argb, int dst_stride_argb, int dest_width, int dest_height) {
    return _frame->ConvertToARGB(libwebrtc::RTCVideoFrame::Type::kRGBA, dst_argb, dst_stride_argb, dest_width, dest_height);
}

RTCVideoRendererImpl::RTCVideoRendererImpl(
    std::shared_ptr<OnTrackInterface> roomOnTrackInterface,
    std::shared_ptr<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>> streamOnTrackInterfacesMap, 
    const std::vector<std::string>& streamIds, 
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track
) : 
    _roomOnTrackInterface(roomOnTrackInterface), _streamOnTrackInterfacesMap(streamOnTrackInterfacesMap), _streamIds(streamIds), _track(track) {
    LOG_TRACE("RTCVideoRendererImpl created")
}
RTCVideoRendererImpl::RTCVideoRendererImpl(const std::vector<std::string>& streamIds, libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track) 
: _roomOnTrackInterface(nullptr), _streamOnTrackInterfacesMap(nullptr), _streamIds(streamIds), _track(track) {
    LOG_TRACE("RTCVideoRendererImpl created")
}
RTCVideoRendererImpl::~RTCVideoRendererImpl() {
    LOG_TRACE("RTCVideoRendererImpl destroyed")
}
void RTCVideoRendererImpl::updateRoomOnTrackInterface(std::shared_ptr<OnTrackInterface> roomOnTrackInterface) {
    std::unique_lock<std::mutex> lock(m);
    _roomOnTrackInterface = roomOnTrackInterface;
}
void RTCVideoRendererImpl::updateStreamOnTrackInterfacesMap(std::shared_ptr<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>> streamOnTrackInterfacesMap) {
    std::unique_lock<std::mutex> lock(m);
    _streamOnTrackInterfacesMap = streamOnTrackInterfacesMap;
}
void RTCVideoRendererImpl::OnFrame(libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame> frame) {
    std::unique_lock<std::mutex> lock(m);
    std::shared_ptr<VideoData> videoData = std::make_unique<VideoData>(_streamIds, _track->id().std_string(), frame->width(), frame->height(), std::make_shared<FrameImpl>(frame));
    if(_roomOnTrackInterface) {
        _roomOnTrackInterface->OnData(videoData);
    }
    if(_streamOnTrackInterfacesMap) {
        for(const auto& streamId: _streamIds) {
            auto OnTrackInterface = _streamOnTrackInterfacesMap->get(streamId);
            if(OnTrackInterface) {
                OnTrackInterface.value()->OnData(videoData);
            }
        }
    }
}