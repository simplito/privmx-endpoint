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
#include <rtc_peerconnection.h>
#include "privmx/endpoint/stream/webrtc/Types.hpp"
#include "privmx/endpoint/stream/webrtc/OnTrackInterface.hpp"
#include "privmx/endpoint/stream/PmxDataChannelObserver.hpp"
#include "privmx/endpoint/stream/DataChannelImpl.hpp"
#include "privmx/endpoint/stream/RTCVideoRendererImpl.hpp"
#include "privmx/endpoint/stream/AudioTrackSinkImpl.hpp"
#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/utils/Logger.hpp>
#include <pmx_frame_cryptor.h>

namespace privmx {
namespace endpoint {
namespace stream {

class PmxPeerConnectionObserver : public libwebrtc::RTCPeerConnectionObserver {
public:
    PmxPeerConnectionObserver(
        libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory,
        const std::string& streamRoomId, 
        std::shared_ptr<privmx::webrtc::KeyStore> keys, 
        const privmx::webrtc::FrameCryptorOptions& options
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

    void setOnTrackInterface(std::shared_ptr<OnTrackInterface> roomOnTrackInterface);
    void addOnTrackInterfaceForSingleStream(const std::string& streamId, std::shared_ptr<OnTrackInterface> streamOnTrackInterface);
    void removeOnTrackInterfaceFormSingleStream(const std::string& streamId);
   
private:
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> _peerConnectionFactory;
    std::string _streamRoomId; 
    std::shared_ptr<privmx::webrtc::KeyStore> _currentKeys;
    privmx::webrtc::FrameCryptorOptions _options;

    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<RTCVideoRendererImpl>> _RTCVideoRenderers;
    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<AudioTrackSinkImpl>> _audioTrackSinks;
    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<DataChannelImpl>> _dataChannels;
    privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<privmx::webrtc::FrameCryptor>> _frameCryptors;

    std::optional<std::function<void(libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate>)>> _onIceCandidate;
    // onTrackInterfaces
    std::shared_mutex _onTrackInterfaceMutex;
    std::shared_ptr<OnTrackInterface> _roomOnTrackInterface;
    std::shared_ptr<privmx::utils::ThreadSaveMap<std::string, std::shared_ptr<OnTrackInterface>>> _streamOnTrackInterfacesMap;
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_PMX_PEER_CONNECTIN_OBSERVER_HPP_
