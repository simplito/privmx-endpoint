#define RTC_DESKTOP_DEVICE
#include <SDL2/SDL.h>
#include <iostream>
#include <libwebrtc.h>
#include <rtc_audio_device.h>
#include <rtc_peerconnection.h>
#include <rtc_frame_cryptor.h>
#include <rtc_desktop_media_list.h>
#include <rtc_desktop_capturer.h>

class FrameCryptorObserver : public libwebrtc::RTCFrameCryptorObserver {
public:
    void OnFrameCryptionStateChanged(const libwebrtc::string participant_id, libwebrtc::RTCFrameCryptionState state) override {
        std::cerr << "OnFrameCryptionStateChanged: " << participant_id.std_string() << " " << (int)state << std::endl;
    }
    int AddRef() const override {return 1;}
    int Release() const override {return 1;}
};

class DesktopCapturerObserver : public libwebrtc::DesktopCapturerObserver {
 public:
  void OnStart(libwebrtc::scoped_refptr<libwebrtc::RTCDesktopCapturer> capturer) override { std::cout << "\n\nDesktop observer: OnStart\n\n" << std::endl;}
  void OnPaused(libwebrtc::scoped_refptr<libwebrtc::RTCDesktopCapturer> capturer) override { std::cout << "\n\nDesktop observer: OnPaused\n\n" << std::endl;}
  void OnStop(libwebrtc::scoped_refptr<libwebrtc::RTCDesktopCapturer> capturer) override { std::cout << "\n\nDesktop observer: OnStop\n\n" << std::endl;}
  void OnError(libwebrtc::scoped_refptr<libwebrtc::RTCDesktopCapturer> capturer) override { std::cout << "\n\nDesktop observer: OnError\n\n" << std::endl;}
};

libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnection> peerConnection[2];

template <typename VideoFrameT>
class RTCVideoRendererImpl : public libwebrtc::RTCVideoRenderer<VideoFrameT> {
public:
    RTCVideoRendererImpl(int w, int h, const std::string& title) : w(w), h(h), title("PrivMX Stream - " + title) {}
    virtual void OnFrame(VideoFrameT frame) override {
        if (renderer == NULL) {
            window = SDL_CreateWindow(title.c_str(), SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, w, h, 0);
            renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
            texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_STREAMING, w, h);
        }
        uint32_t* pixels = new uint32_t[w * h];
        frame->ConvertToARGB(libwebrtc::RTCVideoFrame::Type::kRGBA, (uint8_t*)pixels, 4, w, h);
        SDL_UpdateTexture(texture, NULL, pixels, w * sizeof(uint32_t));
        SDL_RenderClear(renderer); SDL_RenderCopy(renderer, texture, NULL, NULL); SDL_RenderPresent(renderer);
        delete pixels;
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            std::cerr << event.type << std::endl;
            if (event.type == SDL_QUIT) exit(0);
            if (event.type == SDL_WINDOWEVENT) {
                if (event.window.event == SDL_WINDOWEVENT_CLOSE)
                {
                    peerConnection[1]->Close();
                    peerConnection[0]->Close();
                    exit(1);
                }
            }
        }
    }
private:
    SDL_Window* window;
    SDL_Texture* texture;
    SDL_Renderer* renderer = NULL;
    int w, h;
    std::string title;
};

class RTCPeerConnectionObserverImpl : public libwebrtc::RTCPeerConnectionObserver {
public:
    RTCPeerConnectionObserverImpl(int id): id(id) {};
    void OnSignalingState(libwebrtc::RTCSignalingState state) override {

        std::cerr << "State: " << state << std::endl;
    };
    void OnPeerConnectionState(libwebrtc::RTCPeerConnectionState state) override {
        std::cerr << "Peer Conn State " << state << std::endl;
    };
    void OnIceGatheringState(libwebrtc::RTCIceGatheringState state) override {};
    void OnIceConnectionState(libwebrtc::RTCIceConnectionState state) override {};
    void OnIceCandidate(libwebrtc::scoped_refptr<libwebrtc::RTCIceCandidate> candidate) override {
        std::cout << "Local Candidate (Paste this to the other peer after the local description):" << std::endl;
        std::cout << candidate->candidate().std_string() << std::endl;
        std::cout << candidate->sdp_mid().std_string() << std::endl;
        std::cout << candidate->sdp_mline_index() << std::endl << std::endl;
        if (id == 1) {
            peerConnection[0]->AddCandidate(candidate->sdp_mid(), candidate->sdp_mline_index(), candidate->candidate());
        }
        if (id == 0) {
            peerConnection[1]->AddCandidate(candidate->sdp_mid(), candidate->sdp_mline_index(), candidate->candidate());
        }
    };
    void OnAddStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) override {
        std::cout << "STREAM ADDED " << id << std::endl;
        if (id == 1) std::cerr << "STREAM ADDED" << std::endl;
        if (id == 1) {
            std::cerr << "ON REMOTE STREM" << std::endl;
            if (stream->video_tracks().size() > 0) { 
                RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r = new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(768, 432, "Remote");
                stream->video_tracks()[0]->AddRenderer(r);
            }
            std::cout << "STREAM TRACKS SIZE: " << stream->tracks().size() << "video: " << stream->video_tracks().size() << " audio: " << stream->audio_tracks().size() << std::endl;
        }
    };
    void OnRemoveStream(libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> stream) override {
        std::cout << "ON REMOTE STREM " << id << std::endl;
        if (id == 1) {
            std::cerr << "ON REMOTE STREM" << std::endl;
            // RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r = new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(768, 432, "Remote");
            // stream->video_tracks()[0]->AddRenderer(r);
        }
    };
    void OnDataChannel(libwebrtc::scoped_refptr<libwebrtc::RTCDataChannel> data_channel) override {};
    void OnRenegotiationNeeded() override {};
    void OnTrack(libwebrtc::scoped_refptr<libwebrtc::RTCRtpTransceiver> transceiver) override {
        std::cout << "ON TRACK " << id << std::endl;
        if (id == 1) std::cerr << "ONTRACK" << std::endl;
    };
    void OnAddTrack(libwebrtc::vector<libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream>> streams, libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) override {
        std::cout << "TRACK ADDED " << id << std::endl;
        if (id == 1) {
            std::cerr << "TRACK ADDED" << std::endl;
            std::cerr << streams[0]->video_tracks().size() << std::endl;
            // RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r = new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(768, 432, "Remote");
            // streams[0]->video_tracks()[0]->AddRenderer(r);
            // std::cerr << streams[0]->video_tracks()[0]->enabled() << std::endl;
        }
    };
    void OnRemoveTrack(libwebrtc::scoped_refptr<libwebrtc::RTCRtpReceiver> receiver) override {};

private:
    int id;
};

int main() {

    libwebrtc::OnSetSdpSuccess onSetSdpSuccess = [&]() {
        std::cout <<"[SetSdpSuccess]" << std::endl;
    };
    libwebrtc::OnSetSdpFailure onSetSdpFailure = [&](const char* error) {
        std::cout <<"[SetSdpFailure: " << error << "]" << std::endl;
    };

    libwebrtc::OnGetSdpSuccess onGetSdpSuccess = [&](const char* sdp, const char* type) {
        // std::cout <<"[GetSdpSuccess: " << std::endl << sdp << std::endl << "]" << std::endl;
    };
    libwebrtc::OnGetSdpFailure onGetSdpFailure = [&](const char* error) {
        std::cout <<"[GetSdpFailure: " << error << "]" << std::endl;
    };

    libwebrtc::OnSdpCreateSuccess onSdpCreateSuccess = [&](const libwebrtc::string sdp, const libwebrtc::string type) {
        // std::cout <<"[SdpCreateSuccess: " << std::endl << sdp.std_string() << std::endl << "]" << std::endl;
    };
    libwebrtc::OnSdpCreateFailure onSdpCreateFailure = [&](const char* error) {
        std::cout <<"[SdpCreateFailure: " << error << "]" << std::endl;
    };

    SDL_Init(SDL_INIT_VIDEO);

    libwebrtc::LibWebRTC::Initialize();

    libwebrtc::scoped_refptr<libwebrtc::RTCPeerConnectionFactory> peerConnectionFactory = libwebrtc::LibWebRTC::CreateRTCPeerConnectionFactory();


    libwebrtc::RTCConfiguration configuration;
    libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> constraints = libwebrtc::RTCMediaConstraints::Create();
    peerConnection[0] = peerConnectionFactory->Create(configuration, constraints);
    peerConnection[1] = peerConnectionFactory->Create(configuration, constraints);
    RTCPeerConnectionObserverImpl observer0(0);
    RTCPeerConnectionObserverImpl observer1(1);
    // libwebrtc::RTCPeerConnectionObserverImpl peerConnectionObserver2 = libwebrtc::RTCPeerConnectionObserverImpl();
    peerConnection[0]->RegisterRTCPeerConnectionObserver(&observer0);
    peerConnection[1]->RegisterRTCPeerConnectionObserver(&observer1);


    // peerConnectionFactory->Initialize();
    std::cout << "peerConnectionFactory->GetVideoDevice" << std::endl;
    libwebrtc::scoped_refptr<libwebrtc::RTCVideoDevice> videoDevice = peerConnectionFactory->GetVideoDevice();
    std::cout << "videoDevice->NumberOfDevices : " <<  videoDevice->NumberOfDevices() << std::endl;

    uint32_t num = videoDevice->NumberOfDevices();
    std::string name, deviceId;
    name.resize(255);
    deviceId.resize(255);
    for (uint32_t i = 0; i < num; ++i) {
        videoDevice->GetDeviceName(i, (char*)name.data(), name.size(), (char*)deviceId.data(), deviceId.size());
        std::cerr << "Device video " << i << ": " << name << " " << deviceId << std::endl;
    }

    auto audioDevice = peerConnectionFactory->GetAudioDevice();
    num = audioDevice->RecordingDevices();
    for (uint32_t i = 0; i < num; ++i) {
        audioDevice->RecordingDeviceName(i, (char*)name.data(), (char*)deviceId.data());
        std::cerr << "Device audio " << i << ": " << name << " " << deviceId << std::endl;
    }

    // auto audioSource = peerConnectionFactory->CreateAudioSource("x");
    // audioDevice->SetRecordingDevice(0);
    // audioDevice->SetMicrophoneVolume(100);
    // auto audioSource = peerConnectionFactory->CreateAudioSource("audio");
    auto audioTrack = peerConnectionFactory->CreateAudioTrack(peerConnectionFactory->CreateAudioSource("audio"), "audio");
    // audioTrack->SetVolume(100);

    // std::cout << "videoDevice->Create" << std::endl;
    // libwebrtc::scoped_refptr<libwebrtc::RTCVideoCapturer> videoCapturer = videoDevice->Create("test_videoCapturer", 0, 1920, 1080, 60);
    // std::cout << "videoDevice->NumberOfDevices : " <<  videoDevice->NumberOfDevices() << std::endl;
    // std::cout << "peerConnectionFactory->CreateVideoSource" << std::endl;
    // libwebrtc::scoped_refptr<libwebrtc::RTCMediaConstraints> constraints2 = libwebrtc::RTCMediaConstraints::Create();
    // libwebrtc::scoped_refptr<libwebrtc::RTCVideoSource> videoSource = peerConnectionFactory->CreateVideoSource(videoCapturer, "test_videoSource", constraints2);
    // std::cout << "peerConnectionFactory->CreateVideoTrack" << std::endl;
    // libwebrtc::scoped_refptr<libwebrtc::RTCVideoTrack> videoTrack = peerConnectionFactory->CreateVideoTrack(videoSource, "test_videoTrack");

    auto desktopDevice = peerConnectionFactory->GetDesktopDevice();
    auto mediaList = desktopDevice->GetDesktopMediaList(libwebrtc::DesktopType::kScreen);

    mediaList->UpdateSourceList(true);

    std::cerr << "Media list size = " << mediaList->GetSourceCount() << " " << mediaList->type() << std::endl;

    // exit(1);

    auto stream = peerConnectionFactory->CreateStream("stream2");

    auto desktopMediaSource = mediaList->GetSource(0);
    auto desktopCapturer = desktopDevice->CreateDesktopCapturer(desktopMediaSource);
    DesktopCapturerObserver desktopObserver;
    desktopCapturer->RegisterDesktopCapturerObserver(&desktopObserver);
    auto desktopSource = peerConnectionFactory->CreateDesktopSource(desktopCapturer, "desktop", constraints);
    auto desktopTrack = peerConnectionFactory->CreateVideoTrack(desktopSource, "desktop_track");

    auto desktopSource2 = desktopCapturer->source();
    std::cerr << "Desktop name: " << desktopSource2->name().std_string() << " " << desktopSource2->type() << std::endl;

    // exit(1);

    // libwebrtc::scoped_refptr<libwebrtc::RTCMediaStream> mediaStream = peerConnectionFactory->CreateStream("test_mediaStream");
    // std::cout << "mediaStream->AddTrack(" << std::endl;
    // mediaStream->AddTrack(videoTrack);

    // auto desktopDevice = peerConnectionFactory->;

    // RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r = new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(768, 432, "Local");
    // videoTrack->AddRenderer(r);

    RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r2 = new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(768, 432, "Local desktop");
    desktopTrack->AddRenderer(r2);

    // RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r3 = new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(768, 432);
    // videoTrack->AddRenderer(r3);

    // RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>* r4 = new RTCVideoRendererImpl<libwebrtc::scoped_refptr<libwebrtc::RTCVideoFrame>>(768, 432);
    // videoTrack->AddRenderer(r4);

    // peerConnection[0]->AddTrack(videoTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{"stream1"}});
    // peerConnection[0]->AddTrack(audioTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{"stream1"}});
    peerConnection[0]->AddTrack(desktopTrack, libwebrtc::vector<libwebrtc::string>{std::vector<libwebrtc::string>{"stream1"}});
    desktopCapturer->Start(uint32_t(60));
    // videoCapturer->StartCapture();
    // auto state = desktopCapturer->Start(30);

    // int k;std::cin>>k;

    // std::cout << "Is running capturer: " << desktopCapturer->IsRunning() << " state: " << state<< std::endl;

    // libwebrtc::scoped_refptr<libwebrtc::KeyProvider> keyProvider = libwebrtc::KeyProvider::Create(new libwebrtc::KeyProviderOptions());
    // keyProvider->SetKey("ala", 0, std::vector<uint8_t>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    // libwebrtc::scoped_refptr<libwebrtc::RTCRtpSender> sender = peerConnection[0]->senders()[0];
    // libwebrtc::scoped_refptr<libwebrtc::RTCFrameCryptor> frameCryptor = libwebrtc::FrameCryptorFactory::frameCryptorFromRtpSender(peerConnectionFactory, "ala", sender, libwebrtc::Algorithm::kAesGcm, keyProvider);
    // libwebrtc::scoped_refptr<FrameCryptorObserver> cryptorObserver = new FrameCryptorObserver();
    // frameCryptor->RegisterRTCFrameCryptorObserver(cryptorObserver);
    // frameCryptor->SetEnabled(true);

    peerConnection[0]->CreateOffer(
        [&](const libwebrtc::string sdp, const libwebrtc::string type) {
            // std::cout <<"[SdpCreateSuccess: sdp" << std::endl << sdp.std_string() << std::endl << "]" << std::endl;
            // std::cout <<"[SdpCreateSuccess: type" << std::endl << type.std_string() << std::endl << "]" << std::endl;
            peerConnection[0]->SetLocalDescription(sdp, type, onSetSdpSuccess, onSetSdpFailure);
            peerConnection[1]->SetRemoteDescription(sdp, type, onSetSdpSuccess, onSetSdpFailure);
            // std::cerr << "Decription: " << sdp.c_string() << std::endl;
            peerConnection[1]->CreateAnswer([&](const libwebrtc::string sdp, const libwebrtc::string type){
            std::cerr << "Answer: " << sdp.c_string() << std::endl;
                peerConnection[1]->SetLocalDescription(sdp, type, onSetSdpSuccess, onSetSdpFailure);
                peerConnection[0]->SetRemoteDescription(sdp, type, onSetSdpSuccess, onSetSdpFailure);
            }, onGetSdpFailure, constraints);
        },
        [&](const char* error) {
            std::cout <<"[SdpCreateFailure: " << error << "]" << std::endl;
        }, 
        constraints
    );

    int i;
    std::cin >> i;

    peerConnection[0]->RestartIce();
    std::cin >> i;


    // SDL_Event PingStop;
    // while (SDL_WaitEvent(&PingStop)) {
    //     std::cerr << PingStop.type << std::endl;
    //     if (PingStop.type == SDL_QUIT) exit(0);
    // }


    // int i = 0;
    // std::cin >> i;
    //SDL_Delay(30000); SDL_DestroyTexture(texture); SDL_DestroyRenderer(renderer); SDL_DestroyWindow(window); SDL_Quit();
};
