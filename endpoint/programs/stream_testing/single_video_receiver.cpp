#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <memory>
#include <atomic>
#include <mutex>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/Config.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/stream/Events.hpp>
#include <privmx/endpoint/stream/Types.hpp>
#include <privmx/endpoint/stream/webrtc/OnTrackInterface.hpp>
#include <privmx/endpoint/stream/webrtc/Types.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/Logger.hpp>
#include <SDL2/SDL.h>

using namespace std;
using namespace privmx::endpoint;

class RTCVideoRendererImpl {
public:
    RTCVideoRendererImpl(
        const std::string& title, int width, int height
    ) : 
        _title("PrivMX Stream - " + title), _width(width), _height(height), 
        _window(nullptr), _texture(nullptr), _renderer(nullptr),
        _framePixels(std::vector<uint32_t>(_width*_height)), _hasNewFrame(false),
        _stop(false), _SDLMainThread(std::thread(&RTCVideoRendererImpl::main, this))
    {}

    ~RTCVideoRendererImpl() {
        _stop = true;
        if (_SDLMainThread.joinable()) _SDLMainThread.join();
    }
    void OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame)
    {
        std::lock_guard<std::mutex> lock(_frameMutex);
        frame->ConvertToRGBA(
            reinterpret_cast<uint8_t*>(_framePixels.data()),
            4, _width, _height
        );

        _hasNewFrame = true;
    }

private:
    void initializeSDL() {
        if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
            LOG_FATAL("SDL_Init Error: " , SDL_GetError())
            throw "SDL_Error";
        }
        _window = SDL_CreateWindow(_title.c_str(), SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, _width, _height, 0);
        if (!_window) {
            LOG_FATAL("SDL_CreateWindow Error: " , SDL_GetError())
            SDL_Quit();
            throw "SDL_Error";
        }
        _renderer = SDL_CreateRenderer(_window, -1, SDL_RENDERER_ACCELERATED);
        if (!_renderer) {
            LOG_FATAL("SDL_CreateRenderer Error: " , SDL_GetError())
            SDL_DestroyWindow(_window);
            SDL_Quit();
            throw "SDL_Error";
        }
        _texture = SDL_CreateTexture(_renderer, SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_STREAMING, _width, _height);
        if (!_texture) {
            LOG_FATAL("SDL_CreateTexture Error: " , SDL_GetError())
            SDL_DestroyRenderer(_renderer);
            SDL_DestroyWindow(_window);
            SDL_Quit();
            throw "SDL_Error";
        }
    }
    void main() {
        initializeSDL();
        const int frameDelayMs = 1000 / 24; // 24 Frames per second
        while (!_stop) {
            Uint32 startTicks = SDL_GetTicks64();
            SDL_Event event;
            while (SDL_PollEvent(&event)) {
                if (event.type == SDL_QUIT ||
                   (event.type == SDL_WINDOWEVENT &&
                    event.window.event == SDL_WINDOWEVENT_CLOSE)) {
                    _stop = true;
                    exit(0);
                }
            }
            {
                std::lock_guard<std::mutex> lock(_frameMutex);
                if (_hasNewFrame) {
                    SDL_UpdateTexture(
                        _texture,
                        nullptr,
                        _framePixels.data(),
                        _width * sizeof(uint32_t)
                    );
                    _hasNewFrame = false;
                }
            }
            SDL_RenderClear(_renderer);
            SDL_RenderCopy(_renderer, _texture, nullptr, nullptr);
            SDL_RenderPresent(_renderer);

            Uint32 elapsed = SDL_GetTicks64() - startTicks;
            if (elapsed < (Uint32)frameDelayMs) SDL_Delay(frameDelayMs - elapsed);
        }
        if (_texture) SDL_DestroyTexture(_texture);
        if (_renderer) SDL_DestroyRenderer(_renderer);
        if (_window) SDL_DestroyWindow(_window);
        SDL_Quit();
    }

    SDL_Window* _window;
    SDL_Texture* _texture;
    SDL_Renderer* _renderer;

    std::string _title;
    int _width;
    int _height;

    std::mutex _frameMutex;
    std::vector<uint32_t> _framePixels;
    bool _hasNewFrame;

    std::atomic_bool _stop;
    std::thread _SDLMainThread;
};

static vector<string_view> getParamsList(int argc, char* argv[]) {
    vector<string_view> args(argv + 1, argv + argc);
    return args;
}

class OnTrackImpl : public stream::OnTrackInterface {
public:
    OnTrackImpl() : _renderer(RTCVideoRendererImpl("Remote", 768, 432)) {}
    virtual void OnRemoteTrack(stream::Track tack, stream::TrackAction action) override {
        if(tack.kind == stream::DataType::AUDIO) {
            LOG_INFO("OnRemoteTrack[stream::TrackAction] DataType::AUDIO : ", (action == stream::TrackAction::ADDED ? "ADDED" : "REMOVED"));
        }
        if(tack.kind == stream::DataType::VIDEO) {
            LOG_INFO("OnRemoteTrack[stream::TrackAction] DataType::VIDEO : ", (action == stream::TrackAction::ADDED ? "ADDED" : "REMOVED"));
        }
    }
    virtual void OnData(std::shared_ptr<stream::Data> data) override {
        
        if(data->type == stream::DataType::VIDEO) {
            auto videoData = std::dynamic_pointer_cast<stream::VideoData>(data);
            // selecting most active video track to render
            std::lock_guard<std::mutex> lock(mutex);
            if(_videoTrackC == 0) {
                _videoTrack = videoData->track;
            }
            if(_videoTrack == videoData->track) {
                _videoTrackC = 30;
                _renderer.OnFrame(videoData->w, videoData->h, videoData->frameData);
            }
            --_videoTrackC;
        } else if(data->type == stream::DataType::AUDIO) {
            auto audioData = std::dynamic_pointer_cast<stream::AudioData>(data);
        } else if(data->type == stream::DataType::PLAIN) {
            auto plainData = std::dynamic_pointer_cast<stream::PlainData>(data);
            LOG_INFO("Recived plain data", plainData->data.stdString());
        } else {
            LOG_FATAL("DataType::UNKNOWN")
        }
    }
private:
    std::mutex _mutex;
    std::string _videoTrack = "";
    size_t _videoTrackC = 0;
    RTCVideoRendererImpl _renderer;
};

int main(int argc, char** argv) {
    auto params = getParamsList(argc, argv);
    if(params.size() < 4 || params.size() > 5) {
        std::cout << "Invalid params required params are 'PrivKey', 'SolutionId', 'BridgeUrl', 'ContextId', '?StreamRoomId'" << std::endl;
        return -1;
    }
    std::string privKey = {params[0].begin(),  params[0].end()};
    std::string solutionId = {params[1].begin(),  params[1].end()};
    std::string bridgeUrl = {params[2].begin(),  params[2].end()};
    std::string contextId = {params[3].begin(),  params[3].end()};
    std::optional<std::string> streamRoomIdOpt = {nullopt};
    if(params.size() >= 5) {
        streamRoomIdOpt = std::string(params[4].begin(),  params[4].end());
    }
    try {
        core::Connection connection = core::Connection::connect(
            privKey, 
            solutionId, 
            bridgeUrl
        );    
        event::EventApi eventApi = event::EventApi::create(connection);
        stream::StreamApi streamApi = stream::StreamApi::create(connection, eventApi);
        std::string streamRoomId;
        if(streamRoomIdOpt.has_value()) {
            streamRoomId = streamRoomIdOpt.has_value();
        } else {
            auto lastStreamRoom = streamApi.listStreamRooms(contextId, {0, 1, "desc"});
            if(lastStreamRoom.readItems.size() == 0) {
                std::cerr << "No streamRoom on bridge" << std::endl;
                return -1;
            }
            streamRoomId = lastStreamRoom.readItems[0].streamRoomId;
            std::cout << "===============================================================================================" << endl;
            std::cout << "joined streamRoomId: " << streamRoomId << endl;
            std::cout << "===============================================================================================" << endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }

        core::EventQueue eventQueue = core::EventQueue::getInstance();
        auto onTrack = std::make_shared<OnTrackImpl>();
        streamApi.subscribeFor({
            streamApi.buildSubscriptionQuery(stream::EventType::STREAMROOM_UPDATE, stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAMROOM_DELETE, stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_PUBLISH,    stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_UNPUBLISH,  stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_JOIN,       stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_LEAVE,      stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
        });
        std::vector<stream::StreamSubscription> streamsId;
        {
            auto streamlist = streamApi.listStreams(streamRoomId);
            std::cout << "streamlist:" <<  streamlist.size() << std::endl;
            for(auto stream : streamlist) {
                std::cout << "stream.id:" <<  stream.id << std::endl;
                std::cout << "stream.metadata:" << (stream.metadata.has_value() ? stream.metadata.value() : "") << std::endl;
                for(auto track : stream.tracks) {
                    std::cout << "stream.track[].mid:" << track.mid << std::endl;
                    std::cout << "stream.track[].type:" << track.type << std::endl;
                    streamsId.push_back(stream::StreamSubscription{stream.id, track.mid});
                }
                break;
            }
        }
        streamApi.joinStreamRoom(streamRoomId);
        streamApi.addRemoteStreamListener(streamRoomId, std::nullopt, onTrack);
        streamApi.subscribeToRemoteStreams(streamRoomId, streamsId);

        auto eventThread = std::thread([&](){
            while (true) {
                auto eventHolder = eventQueue.waitEvent();
                if(core::Events::isLibBreakEvent(eventHolder)) return;
                if(stream::Events::isStreamUpdatedEvent(eventHolder)) {
                    auto streamUpdatedEvent = stream::Events::extractStreamUpdatedEvent(eventHolder).data;
                    auto streamsModified = streamUpdatedEvent.streamsModified;

                    std::vector<stream::StreamSubscription> toAddstreamsId;
                    std::vector<stream::StreamSubscription> toRemovestreamsId;
                    for(auto stream : streamsModified) {
                        for(auto track : stream.tracks) {
                            if(track.after.has_value()) {
                                if(track.after.value().disabled.has_value()) {
                                    toRemovestreamsId.push_back({stream.streamId, track.after.value().mid});
                                } else {
                                    toAddstreamsId.push_back({stream.streamId, track.after.value().mid});
                                } 
                            }
                            
                        }
                    }
                    if(toAddstreamsId.size() > 0 || toRemovestreamsId.size() > 0) {
                        streamApi.modifyRemoteStreamsSubscriptions(streamRoomId, toAddstreamsId, toRemovestreamsId);
                    }
                }
            }
        });
        
        std::this_thread::sleep_for(std::chrono::seconds(600));
        eventQueue.emitBreakEvent();
        if(eventThread.joinable()) eventThread.join();
        connection.disconnect();
       
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


