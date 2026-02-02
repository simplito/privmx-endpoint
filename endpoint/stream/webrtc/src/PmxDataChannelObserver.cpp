/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/PmxDataChannelObserver.hpp"
using namespace privmx::endpoint::stream;



PmxDataChannelObserver::PmxDataChannelObserver(std::shared_ptr<OnTrackInterface> onTrackInterface, const std::string& dataChannelId) 
    : _onTrackInterface(onTrackInterface), _dataChannelId(dataChannelId) {

}
void PmxDataChannelObserver::OnStateChange(libwebrtc::RTCDataChannelState state) {
    if(state == libwebrtc::RTCDataChannelState::RTCDataChannelOpen) {
        if(_onTrackInterface) {
            _onTrackInterface->OnRemoteTrack(
                Track{
                    DataType::PLAIN, 
                    std::vector<std::string>{}, 
                    _dataChannelId, 
                    false, 
                    [](bool mute) {return;}}, 
                TrackAction::ADDED
            );
        }
    } else if(state == libwebrtc::RTCDataChannelState::RTCDataChannelClosing) {
        if(_onTrackInterface) {
            _onTrackInterface->OnRemoteTrack(
                Track{
                    DataType::PLAIN, 
                    std::vector<std::string>{}, 
                    _dataChannelId, 
                    false, 
                    [](bool mute) {return;}}, 
                TrackAction::REMOVED
            );
        }
    } 
}
void PmxDataChannelObserver::OnMessage(const char* buffer, int length, bool binary) {
    std::shared_ptr<PlainData> data = std::make_shared<PlainData>(std::vector<std::string>{}, _dataChannelId, std::string(buffer, length), binary);
    std::lock_guard<std::mutex> lock(_onTrackInterfaceMutex);
    //To Add Decryption
    if(_onTrackInterface) {
        _onTrackInterface->OnData(data);
    }
}
   
void PmxDataChannelObserver::updateOnTrackInterface(std::shared_ptr<OnTrackInterface> onTrackInterface) {
    std::lock_guard<std::mutex> lock(_onTrackInterfaceMutex);
    _onTrackInterface = onTrackInterface;
}


