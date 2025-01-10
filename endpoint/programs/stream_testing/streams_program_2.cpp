#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
// #include <privmx/utils/IniFileReader.hpp>
#include <privmx/endpoint/core/Exception.hpp>

#include <privmx/endpoint/core/Config.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/crypto/CryptoApi.hpp>
#include <libwebrtc.h>
#include <rtc_audio_device.h>
#include <rtc_peerconnection.h>
#include <base/portable.h>
#include <rtc_mediaconstraints.h>
#include <rtc_peerconnection.h>
#include <privmx/utils/PrivmxException.hpp>

using namespace std;
using namespace privmx::endpoint;



#define PRINT_LIST(list, f1, f2)                \
    cout << #list << " list:" << endl;  \
    for (const auto& item : list) {                    \
        cout << #f1 << ": " << item.f1 << ", " << #f2 << ": " << item.f2 << endl;    \
    }


static vector<string_view> getParamsList(int argc, char* argv[]) {
    vector<string_view> args(argv + 1, argv + argc);
    return args;
}

static string readFile(const string filePath) {
    // string homeDir{getenv("HOME")};
    // string fName{"testImg.png"};
    // string fPath{homeDir + "/" + fName};
    ifstream input(filePath, ios::binary);
    stringstream strStream;
    strStream << input.rdbuf();
    return strStream.str();
}

namespace privmx {
namespace endpoint {
namespace stream {

/**
 * Our implementation of the RTCPeerConnectionObserver.
 * 
 * Requires adding implementation, including sending ICE candidates to the remote peer via Bridge.
*/
class PmxPeerConnectionObserver : public libwebrtc::RTCPeerConnectionObserver {
public:
    PmxPeerConnectionObserver(std::string label) : _label(label) {};
    void OnSignalingState(libwebrtc::RTCSignalingState state) override {
        std::cout << "==========================" << std::endl;
        std::cout << _label + ": " << "ON SIGNALING STATE" << std::endl;
        std::cout << "==========================" << std::endl;
    };
    void OnPeerConnectionState(libwebrtc::RTCPeerConnectionState state) override {
        std::cout << "==========================" << std::endl;
        std::cout << _label + ": " << "ON PEER CONNECTION STATE" << std::endl;
        std::cout << "==========================" << std::endl;
    };
    void OnIceGatheringState(libwebrtc::RTCIceGatheringState state) override {};
    void OnIceConnectionState(libwebrtc::RTCIceConnectionState state) override {};
    void OnIceCandidate(libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate> candidate) override {
        // TODO: Send candidate to remote peer over Bridge
    };
    void OnAddStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) override {
        std::cout << "==========================" << std::endl;
        std::cout << _label + ": " << "STREAM ADDED" << std::endl;
        std::cout << "stream->video_tracks().size() -> " << stream->video_tracks().size() << std::endl;
        std::cout << "stream->audio_tracks().size() -> " << stream->audio_tracks().size() << std::endl;
        std::cout << "==========================" << std::endl;
    };
    void OnRemoveStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) override {};
    void OnDataChannel(libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> data_channel) override {};
    void OnRenegotiationNeeded() override {};
    void OnTrack(libwebrtc::scoped_refptr<libwebrtc::RTCRtpTransceiver> transceiver) override {
        std::cout << "==========================" << std::endl;
        std::cout << _label + ": " << "ON TRACK" << std::endl;
        std::cout << "==========================" << std::endl;
    };
    void OnAddTrack(libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>> streams, libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) override {
        std::cout << "==========================" << std::endl;
        std::cout << _label + ": " << "TRACK ADDED" << std::endl;
        std::cout << "==========================" << std::endl;
    };
    void OnRemoveTrack(libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) override {};
private:
    std::string _label;
};

class PmxWebRtc
{
public:
    /**
     * Initializes the WebRTC library at runtime.
     * 
     * Call this function once at runtime.
    */
    void initialize() {
        // Initialize WebRTC
        libwebrtc::LibWebRTC::Initialize();

        // Create instance of RTCPeerConnectionFactory
        peerConnectionFactory = libwebrtc::LibWebRTC::CreateRTCPeerConnectionFactory();
    }

    /**
     * Creates audio-video streams and creates new peer connection.
     * 
     * Requires implementation of offer and candidate sending handling by Bridge.
    */
    std::string createStream(libwebrtc::RTCConfiguration configuration) {
        // Create configuration and constraints
        libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> constraints = libwebrtc::RTCMediaConstraints::Create();

        // Create peer connection
        senderPeerConnection = peerConnectionFactory->Create(configuration, constraints);

        // Register our implementation of the peer connection observer
        senderPeerConnection->RegisterRTCPeerConnectionObserver(&senderObserver);

        // Create audio track
        //List audio device
        std::string name, deviceId;
        name.resize(255);
        deviceId.resize(255);
        auto audioDevice = peerConnectionFactory->GetAudioDevice();
        uint32_t num = audioDevice->RecordingDevices();
        for (uint32_t i = 0; i < num; ++i) {
            audioDevice->RecordingDeviceName(i, (char*)name.data(), (char*)deviceId.data());
            std::cout << "==========================" << std::endl;
            std::cout << "Device audio - " << i << ": " << name  << std::endl;
            std::cout << "Device audio - " << deviceId << std::endl;
            std::cout << "==========================" << std::endl;
        }


        // audioDevice->SetRecordingDevice(0);
        // audioDevice->SetMicrophoneVolume(100);
        auto audioSource = peerConnectionFactory->CreateAudioSource("audio_source");
        auto audioTrack = peerConnectionFactory->CreateAudioTrack(audioSource, "audio_track");
        audioTrack->SetVolume(10);

        senderPeerConnection->AddTrack(audioTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{"stream1"}});

        // Create video track
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = peerConnectionFactory->GetVideoDevice();
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer> videoCapturer = videoDevice->Create("video_capturer", 0, 1280, 720, 30);
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource> videoSource = peerConnectionFactory->CreateVideoSource(videoCapturer, "video_source", constraints);
        libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack = peerConnectionFactory->CreateVideoTrack(videoSource, "video_track");

        // Add tracks to the peer connection
        senderPeerConnection->AddTrack(videoTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{"stream1"}});

        // Start capture video
        // videoCapturer->StartCapture();

        // Create offer
        senderPeerConnection->CreateOffer(
            std::bind(&PmxWebRtc::onSdpCreateSuccessSender, this, std::placeholders::_1, std::placeholders::_2), 
            std::bind(&PmxWebRtc::onSdpCreateFailureSender, this, std::placeholders::_1), 
            constraints
        );
        return _sdp_sender.get_future().get();
    }
    std::string joinStream(libwebrtc::RTCConfiguration configuration, const libwebrtc::string sdp, const libwebrtc::string type) {
        // Create configuration and constraints
        libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> constraints = libwebrtc::RTCMediaConstraints::Create();

        // Create peer connection
        receiverPeerConnection = peerConnectionFactory->Create(configuration, constraints);
        receiverPeerConnection->RegisterRTCPeerConnectionObserver(&receiverObserver);

        receiverPeerConnection->SetRemoteDescription(sdp, type, std::bind(&PmxWebRtc::onSetSdpSuccess, this), std::bind(&PmxWebRtc::onSetSdpFailure, this, std::placeholders::_1));
        receiverPeerConnection->CreateAnswer(
            std::bind(&PmxWebRtc::onSdpCreateSuccessReceiver, this, std::placeholders::_1, std::placeholders::_2), 
            std::bind(&PmxWebRtc::onSdpCreateFailureReceiver, this, std::placeholders::_1), 
            constraints
        );
        // Create offer
        return _sdp_receiver.get_future().get();
    }
    /**
     * Sets the answer from the remote peer.
    */
    void onRemoteAnswer(const libwebrtc::string sdp, const libwebrtc::string type) {
        senderPeerConnection->SetRemoteDescription(sdp, type, std::bind(&PmxWebRtc::onSetSdpSuccess, this), std::bind(&PmxWebRtc::onSetSdpFailure, this, std::placeholders::_1));
    }

    /**
     * Sets remote peer's ICE candidates.
    */
    void onRemoteIceCandidate(libwebrtc::string mid, int mid_mline_index, libwebrtc::string candiate) {
        senderPeerConnection->AddCandidate(mid, mid_mline_index, candiate);
    }

    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> getPeerConnectionFactory() {
        return peerConnectionFactory;
    }

private:
    void onSdpCreateSuccessSender(const libwebrtc::string sdp, const libwebrtc::string type) {
        _sdp_sender.set_value(sdp.std_string());
        // Set local description
        senderPeerConnection->SetLocalDescription(sdp, type, std::bind(&PmxWebRtc::onSetSdpSuccess, this), std::bind(&PmxWebRtc::onSetSdpFailure, this, std::placeholders::_1));
        // TODO: Send offer to the remote peer over Bridge
    }
    void onSdpCreateFailureSender(const char* error) {
        _sdp_sender.set_exception(make_exception_ptr(error));
    }
     
    void onSdpCreateSuccessReceiver(const libwebrtc::string sdp, const libwebrtc::string type) {
        _sdp_receiver.set_value(sdp.std_string());
        // Set local description
        receiverPeerConnection->SetLocalDescription(sdp, type, std::bind(&PmxWebRtc::onSetSdpSuccess, this), std::bind(&PmxWebRtc::onSetSdpFailure, this, std::placeholders::_1));

           // TODO: Send offer to the remote peer over Bridge
    }
    void onSdpCreateFailureReceiver(const char* error) {
        _sdp_receiver.set_exception(make_exception_ptr(error));
    }

    void onSetSdpSuccess() {}
    void onSetSdpFailure(const char* error) {}

    PmxPeerConnectionObserver senderObserver = PmxPeerConnectionObserver("SENDER");
    PmxPeerConnectionObserver receiverObserver = PmxPeerConnectionObserver("RECEIVER");
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory;
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnection> senderPeerConnection;
    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnection> receiverPeerConnection;
    std::promise<std::string> _sdp_sender = std::promise<std::string>();
    std::promise<std::string> _sdp_receiver = std::promise<std::string>();
};

} // namespace stream
} // namespace endpoint
} // namespace privmx


int main(int argc, char** argv) {

    auto params = getParamsList(argc, argv);

    try {
        crypto::CryptoApi cryptoApi = crypto::CryptoApi::create();
        core::Connection connection = core::Connection::connect("L3DdgfGagr2yGFEHs1FcRQRGrpa4nwQKdPcfPiHxcDcZeEb3wYaN", "fc47c4e4-e1dc-414a-afa4-71d436398cfc", "http://webrtc2.s24.simplito.com:3000");
        
        auto connectionImpl = connection.getImpl();
        auto gateway = connectionImpl->getGateway();


        Poco::JSON::Object::Ptr tmp = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        tmp->set("clientId", "user1");
        privmx::rpc::MessageSendOptionsEx settings;
        settings.channel_type = privmx::rpc::ChannelType::WEBSOCKET;
        auto result = gateway->request("stream.streamGetTurnCredentials", tmp, settings).extract<Poco::JSON::Object::Ptr>();
        std::cout << privmx::utils::Utils::stringifyVar(result, true) << std::endl;

        privmx::endpoint::stream::PmxWebRtc pmxWebRtc;

        libwebrtc::IceServer iceServer = {
            .uri="turn:webrtc2.s24.simplito:3478", 
            .username=portable::string(result->getValue<std::string>("username")), 
            .password=portable::string(result->getValue<std::string>("password"))
        };
        libwebrtc::RTCConfiguration configuration;
        configuration.ice_servers[0] = iceServer;
        pmxWebRtc.initialize();

        
        auto sdp_publish = pmxWebRtc.createStream(configuration);
        // cout <<"[Sdp" << endl << sdp << endl << "]" << endl;
        auto sessionDescription = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        sessionDescription->set("sdp", sdp_publish);
        sessionDescription->set("type", "offer");

        tmp = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        tmp->set("streamRoomId", 1234);
        tmp->set("offer", sessionDescription);
        result = gateway->request("stream.streamPublish", tmp, settings).extract<Poco::JSON::Object::Ptr>();
        // std::cout << "stream.streamPublish" << std::endl;
        // std::cout << privmx::utils::Utils::stringifyVar(result, true) << std::endl;
        pmxWebRtc.onRemoteAnswer(result->getObject("answer")->getValue<std::string>("sdp"), result->getObject("answer")->getValue<std::string>("type"));
        std::this_thread::sleep_for(std::chrono::seconds(1));
        tmp = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        tmp->set("streamRoomId", 1234);
        settings.channel_type = privmx::rpc::ChannelType::WEBSOCKET;
        result = gateway->request("stream.streamList", tmp, settings).extract<Poco::JSON::Object::Ptr>();
        // std::cout << "stream.streamList" << std::endl;
        // std::cout << privmx::utils::Utils::stringifyVar(result, true) << std::endl;

        tmp = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        auto streamIds = Poco::JSON::Array::Ptr(new Poco::JSON::Array());
        auto streamList = result->getArray("list");
        for(int i = 0; i < streamList->size(); i++) {
            auto l = streamList->getObject(i);
            streamIds->add(l->getValue<int64_t>("streamId"));
        }
        tmp->set("streamRoomId", 1234);
        tmp->set("streamIds", streamIds);
        settings.channel_type = privmx::rpc::ChannelType::WEBSOCKET;
        result = gateway->request("stream.streamJoin", tmp, settings).extract<Poco::JSON::Object::Ptr>();
        std::cout << "stream.streamJoin" << std::endl;
        std::cout << privmx::utils::Utils::stringifyVar(result, true) << std::endl;
        auto sdp_join = pmxWebRtc.joinStream(configuration, result->getObject("offer")->getValue<std::string>("sdp"), result->getObject("offer")->getValue<std::string>("type"));
        tmp = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        // tmp->set("streamRoomId", 1234);
        tmp->set("sessionId", result->getValue<int64_t>("sessionId"));
        auto sessionAnswer = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        sessionAnswer->set("sdp", sdp_join);
        sessionAnswer->set("type", "answer");
        tmp->set("answer", sessionAnswer);
        auto t_result = gateway->request("stream.streamAcceptOffer", tmp, settings);
        // std::cout << "stream.streamAcceptOffer" << std::endl;
        // std::cout << privmx::utils::Utils::stringifyVar(t_result, true) << std::endl;



        std::this_thread::sleep_for(std::chrono::seconds(120));
        // tmp = Poco::JSON::Object::Ptr(new Poco::JSON::Object());
        // tmp->set("sessionId", result->getValue<int64_t>("sessionId"));
        // settings.channel_type = privmx::rpc::ChannelType::WEBSOCKET;
        // result = gateway->request("stream.streamUnpublish", tmp, settings).extract<Poco::JSON::Object::Ptr>();
    } catch (const core::Exception& e) {
        cerr << e.getFull() << endl;
    } catch (const privmx::utils::PrivmxException& e) {
        cerr << e.what() << endl;
        cerr << e.getData() << endl;
        cerr << e.getCode() << endl;
    } catch (const exception& e) {
        cerr << e.what() << endl;
    } catch (...) {
        cerr << "Error" << endl;
    }

    return 0;
}


