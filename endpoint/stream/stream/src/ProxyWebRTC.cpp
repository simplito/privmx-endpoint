#include "privmx/endpoint/stream/ProxyWebRTC.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

ProxyWebRTC::ProxyWebRTC(
    privmx_endpoint_stream_WebRTCInterface webRTCInterface
) : _webRTCInterface(webRTCInterface) {}

std::string ProxyWebRTC::createOfferAndSetLocalDescription(const std::string& streamRoomId) {
    if (_webRTCInterface.createOfferAndSetLocalDescriptionCallback == nullptr) {
        throw NullCallbackException("CreateOfferAndSetLocalDescriptionCallback");
    }
    const char* result = _webRTCInterface.createOfferAndSetLocalDescriptionCallback(_webRTCInterface.ctx, streamRoomId.c_str());
    return std::string(result);
}

std::string ProxyWebRTC::createAnswerAndSetDescriptions(const std::string& streamRoomId, const std::string& sdp, const std::string& type) {
    if (_webRTCInterface.createAnswerAndSetDescriptionsCallback == nullptr) {
        throw NullCallbackException("CreateAnswerAndSetDescriptionsCallback");
    }
    const char* result = _webRTCInterface.createAnswerAndSetDescriptionsCallback(_webRTCInterface.ctx, streamRoomId.c_str(), sdp.c_str(), type.c_str());
    return std::string(result);
}

void ProxyWebRTC::setAnswerAndSetRemoteDescription(const std::string& streamRoomId, const std::string& sdp, const std::string& type) {
    if (_webRTCInterface.setAnswerAndSetRemoteDescriptionCallback == nullptr) {
        throw NullCallbackException("SetAnswerAndSetRemoteDescriptionCallback");
    }
    _webRTCInterface.setAnswerAndSetRemoteDescriptionCallback(_webRTCInterface.ctx, streamRoomId.c_str(), sdp.c_str(), type.c_str());
}

void ProxyWebRTC::updateSessionId(const std::string& streamRoomId, const int64_t sessionId, const std::string& connectionType) {
    if (_webRTCInterface.updateSessionIdCallback == nullptr) {
        throw NullCallbackException("UpdateSessionIdCallback");
    }
    _webRTCInterface.updateSessionIdCallback(_webRTCInterface.ctx, streamRoomId.c_str(), sessionId, connectionType.c_str());
}

void ProxyWebRTC::close(const std::string& streamRoomId) {
    if (_webRTCInterface.closeCallback == nullptr) {
        throw NullCallbackException("CloseCallback");
    }
    _webRTCInterface.closeCallback(_webRTCInterface.ctx, streamRoomId.c_str());
}

void ProxyWebRTC::updateKeys(const std::string& streamRoomId, const std::vector<Key>& keys) {
    if (_webRTCInterface.updateKeysCallback == nullptr) {
        throw NullCallbackException("UpdateKeysCallback");
    }
    std::shared_ptr<privmx_endpoint_stream_Key> keys_c = mapKeys(keys);
    _webRTCInterface.updateKeysCallback(_webRTCInterface.ctx, streamRoomId.c_str(), keys_c.get(), keys.size());
}

std::shared_ptr<privmx_endpoint_stream_Key> ProxyWebRTC::mapKeys(const std::vector<Key>& keys) {
    std::shared_ptr<privmx_endpoint_stream_Key> keys_c(new privmx_endpoint_stream_Key[keys.size()], [](privmx_endpoint_stream_Key* p){ delete[] p; });
    for (size_t i = 0; i < keys.size(); ++i) {
        auto& key = keys[i];
        auto& key_c = keys_c.get()[i];
        key_c.keyId = key.keyId.c_str();
        key_c.key = reinterpret_cast<const unsigned char*>(key.key.data());
        key_c.keySize = key.key.size();
        key_c.type = mapKeyType(key.type);
    }
    return keys_c;
}

privmx_endpoint_stream_KeyType ProxyWebRTC::mapKeyType(KeyType type) {
    switch (type) {
        case LOCAL:
            return privmx_endpoint_stream_KeyType_LOCAL;
        case REMOTE:
            return privmx_endpoint_stream_KeyType_REMOTE;
    }
    throw UnknownTypeException(std::to_string(type));
}
