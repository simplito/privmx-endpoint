/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_PMX_PEER_CONNECTIN_OBSERVER_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_PMX_PEER_CONNECTIN_OBSERVER_HPP_

#include <string>
#include <libwebrtc.h>
#include <rtc_audio_device.h>
#include <rtc_peerconnection.h>
#include "privmx/endpoint/stream/webrtc/Types.hpp"
#include "privmx/endpoint/stream/webrtc/OnTrackInterface.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/utils/Logger.hpp>
#include <pmx_frame_cryptor.h>

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


template <typename VideoFrameT>
class RTCVideoRendererImpl : public libwebrtc::RTCVideoRenderer<VideoFrameT> {
public:
    inline RTCVideoRendererImpl(std::shared_ptr<OnTrackInterface> onTrackInterface, const std::vector<std::string>& streamIds, libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track) 
    : _onTrackInterface(onTrackInterface), _streamIds(streamIds), _track(track) {
        LOG_TRACE("RTCVideoRendererImpl created")
    }
    inline RTCVideoRendererImpl(const std::vector<std::string>& streamIds, libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track) 
    : _onTrackInterface(nullptr), _streamIds(streamIds), _track(track) {
        LOG_TRACE("RTCVideoRendererImpl created")
    }
    inline ~RTCVideoRendererImpl() {
        LOG_TRACE("RTCVideoRendererImpl destroyed")
    }
    void updateOnTrackInterface(std::shared_ptr<OnTrackInterface> onTrackInterface) {
        std::unique_lock<std::mutex> lock(m);
        _onTrackInterface = onTrackInterface;
    }
    virtual void OnFrame(VideoFrameT frame) override {
        if(_onTrackInterface) {
            std::unique_lock<std::mutex> lock(m);
            std::shared_ptr<VideoData> videoData = std::make_unique<VideoData>(DataType::VIDEO, _streamIds, _track->id().std_string(), frame->width(), frame->height(), std::make_shared<FrameImpl>(frame));
            _onTrackInterface->OnData(videoData);
        }
    }
private:
    std::mutex m;
    std::shared_ptr<OnTrackInterface> _onTrackInterface;
    std::vector<std::string> _streamIds;
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> _track;
};

class AudioTrackSinkImpl : public libwebrtc::AudioTrackSink {
public:
    inline AudioTrackSinkImpl(std::shared_ptr<OnTrackInterface> onTrackInterface, const std::vector<std::string>& streamIds, libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track) 
    : _onTrackInterface(onTrackInterface), _streamIds(streamIds), _track(track) {
        LOG_TRACE("AudioTrackSinkImpl created")
    }
    inline AudioTrackSinkImpl(const std::vector<std::string>& streamIds, libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> track) 
    : _onTrackInterface(nullptr), _streamIds(streamIds), _track(track) {
        LOG_TRACE("AudioTrackSinkImpl created")
    }
    inline ~AudioTrackSinkImpl() {
        LOG_TRACE("AudioTrackSinkImpl destroyed")
    }
    void updateOnTrackInterface(std::shared_ptr<OnTrackInterface> onTrackInterface) {
        std::unique_lock<std::mutex> lock(m);
        _onTrackInterface = onTrackInterface;
    }
    virtual void OnData(const void* audio_data, int bits_per_sample, int sample_rate, size_t number_of_channels, size_t number_of_frames) override {
        if(_onTrackInterface) {
            std::unique_lock<std::mutex> lock(m);
            std::shared_ptr<AudioData> audioData = std::make_unique<AudioData>(DataType::AUDIO, _streamIds, _track->id().std_string(), audio_data, bits_per_sample, sample_rate, number_of_channels, number_of_frames);
            _onTrackInterface->OnData(audioData);
        }
    }
private:
    std::mutex m;
    std::shared_ptr<OnTrackInterface> _onTrackInterface;
    std::vector<std::string> _streamIds;
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> _track;
};

class PmxPeerConnectionObserver : public libwebrtc::RTCPeerConnectionObserver {
public:
    PmxPeerConnectionObserver(
        libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory,
        const std::string& streamRoomId, 
        std::shared_ptr<privmx::webrtc::KeyStore> keys, 
        const privmx::webrtc::FrameCryptorOptions& options,
        std::shared_ptr<OnTrackInterface> onTrackInterface = nullptr
    );
    void OnSignalingState(libwebrtc::RTCSignalingState state) override;
    void OnPeerConnectionState(libwebrtc::RTCPeerConnectionState state) override;
    void OnIceGatheringState(libwebrtc::RTCIceGatheringState state) override;
    void OnIceConnectionState(libwebrtc::RTCIceConnectionState state) override;
    void OnIceCandidate(libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate> candidate) override;
    void OnAddStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) override;
    void OnRemoveStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) override;
    void OnDataChannel(libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> data_channel) override;
    void OnRenegotiationNeeded() override;
    void OnTrack(libwebrtc::scoped_refptr<libwebrtc::RTCRtpTransceiver> transceiver) override;
    void OnAddTrack(libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>> streams, libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) override;
    void OnRemoveTrack(libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) override;

    void UpdateCurrentKeys(std::shared_ptr<privmx::webrtc::KeyStore> newKeys);
    void SetFrameCryptorOptions(privmx::webrtc::FrameCryptorOptions options);

    inline void setOnIceCandidate(std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate>)> callback) {_onIceCandidate = callback;}
    void setOnTrackInterface(std::shared_ptr<OnTrackInterface> onTrackInterface);
   
private:
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> _peerConnectionFactory;
    std::string _streamRoomId; 
    std::shared_ptr<privmx::webrtc::KeyStore> _currentKeys;
    privmx::webrtc::FrameCryptorOptions _options;

    std::shared_ptr<OnTrackInterface> _onTrackInterface;
    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>>> _RTCVideoRenderers;
    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<AudioTrackSinkImpl>> _audioTrackSinks;

    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<privmx::webrtc::FrameCryptor>> _frameCryptors;

    std::optional<std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate>)>> _onIceCandidate;
    // tmp
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaTrack> tmpTrack;
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_PMX_PEER_CONNECTIN_OBSERVER_HPP_
