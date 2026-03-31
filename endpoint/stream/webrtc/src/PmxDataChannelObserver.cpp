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


PmxDataChannelObserver::PmxDataChannelObserver(std::shared_ptr<OnTrackInterface> onTrackInterface, std::shared_ptr<DataChannelMessageEncryptorV1> messageEncryptor, const std::string& dataChannelId) 
    : _onTrackInterface(onTrackInterface), _messageEncryptor(messageEncryptor), _dataChannelId(dataChannelId) {
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
    //To Add Decryption
    if(_onTrackInterface && _messageEncryptor) {
        try {
            auto decryptedData = _messageEncryptor->decryptMessage(core::Buffer::from(std::string(buffer, length)));
            std::shared_ptr<PlainData> data = std::make_shared<PlainData>(std::vector<std::string>{}, _dataChannelId, decryptedData.first, decryptedData.second, binary);
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


