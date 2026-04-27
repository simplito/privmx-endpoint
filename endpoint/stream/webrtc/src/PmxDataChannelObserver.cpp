/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/PmxDataChannelObserver.hpp"
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/utils/Logger.hpp>

using namespace privmx::endpoint::stream;


PmxDataChannelObserver::PmxDataChannelObserver(std::shared_ptr<OnTrackInterface> onTrackInterface, std::shared_ptr<StreamApiLow> apiLow, const std::string& dataChannelId, const std::string& streamRoomId) 
    : _onTrackInterface(onTrackInterface), _apiLow(apiLow), _dataChannelId(dataChannelId), _streamRoomId(streamRoomId) {
    LOG_TRACE("PmxDataChannelObserver created")
}
void PmxDataChannelObserver::OnStateChange(libwebrtc::RTCDataChannelState state) {
    if(state == libwebrtc::RTCDataChannelState::RTCDataChannelConnecting) {
        LOG_INFO("PmxDataChannelObserver::OnStateChange::RTCDataChannelConnecting")
    } else if(state == libwebrtc::RTCDataChannelState::RTCDataChannelOpen) {
        LOG_INFO("PmxDataChannelObserver::OnStateChange::RTCDataChannelOpen")
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
        LOG_INFO("PmxDataChannelObserver::OnStateChange::RTCDataChannelClosing")
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
    } else if(state == libwebrtc::RTCDataChannelState::RTCDataChannelClosed) {
        LOG_INFO("PmxDataChannelObserver::OnStateChange::RTCDataChannelClosed")
    }
}
void PmxDataChannelObserver::OnMessage(const char* buffer, int length, bool binary) {
    std::lock_guard<std::mutex> lock(_onTrackInterfaceMutex);
    if(_onTrackInterface) {
        try {
            auto decryptedData = _apiLow->decryptDataChannelMessage(_streamRoomId, core::Buffer::from(std::string(buffer, length)));
            std::shared_ptr<PlainData> data = std::make_shared<PlainData>(std::vector<std::string>{}, _dataChannelId, decryptedData.data, decryptedData.seq, binary, decryptedData.statusCode);
            LOG_DEBUG("_onTrackInterface->OnData(data): ", data)
            _onTrackInterface->OnData(data);
        }  catch (const privmx::endpoint::core::Exception& e) {
            LOG_ERROR("PmxDataChannelObserver::OnMessage recived privmx::endpoint::core::Exception\n", e.getFull())
        } catch (const privmx::utils::PrivmxException& e) {
            LOG_ERROR("PmxDataChannelObserver::OnMessage recived privmx::utils::PrivmxException\n", e.what(), " ", e.getCode())
        } catch (...) {
            LOG_ERROR("PmxDataChannelObserver::OnMessage recived unknown exception")
        }
    }
}
   
void PmxDataChannelObserver::updateOnTrackInterface(std::shared_ptr<OnTrackInterface> onTrackInterface) {
    std::lock_guard<std::mutex> lock(_onTrackInterfaceMutex);
    _onTrackInterface = onTrackInterface;
}


