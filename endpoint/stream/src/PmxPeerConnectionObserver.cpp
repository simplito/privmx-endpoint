/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include <privmx/endpoint/stream/PmxPeerConnectionObserver.hpp>

using namespace privmx::endpoint::stream;

PmxPeerConnectionObserver::PmxPeerConnectionObserver() {};
void PmxPeerConnectionObserver::OnSignalingState(libwebrtc::RTCSignalingState state) {

}
void PmxPeerConnectionObserver::OnPeerConnectionState(libwebrtc::RTCPeerConnectionState state) {

}
void PmxPeerConnectionObserver::OnIceGatheringState(libwebrtc::RTCIceGatheringState state) {

}
void PmxPeerConnectionObserver::OnIceConnectionState(libwebrtc::RTCIceConnectionState state) {

}
void PmxPeerConnectionObserver::OnIceCandidate(libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate> candidate) {
    // TODO: Send candidate to remote peer over Bridge
}
void PmxPeerConnectionObserver::OnAddStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) {

}
void PmxPeerConnectionObserver::OnRemoveStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) {

}
void PmxPeerConnectionObserver::OnDataChannel(libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> data_channel) {

}
void PmxPeerConnectionObserver::OnRenegotiationNeeded() {

};
void PmxPeerConnectionObserver::OnTrack(libwebrtc::scoped_refptr<libwebrtc::RTCRtpTransceiver> transceiver) {

}
void PmxPeerConnectionObserver::OnAddTrack(libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>> streams, libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {
    
}
void PmxPeerConnectionObserver::OnRemoveTrack(libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) {

}


