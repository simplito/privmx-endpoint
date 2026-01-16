#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <memory>
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
#include <privmx/utils/Debug.hpp>
#include <privmx/utils/Logger.hpp>
#include <SDL2/SDL.h>

using namespace std;
using namespace privmx::endpoint;

class RTCVideoRendererImpl {
public:
    RTCVideoRendererImpl(const std::string& title) : title("PrivMX Stream - " + title) {}
    void OnFrame(int64_t w, int64_t h, std::shared_ptr<privmx::endpoint::stream::Frame> frame, const std::string id) {
        if (renderer == NULL) {
            window = SDL_CreateWindow(title.c_str(), SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 768, 432, 0);
            renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
            texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_STREAMING, 768, 432);
            windowEventsLoop();
        }
        uint32_t* pixels = new uint32_t[768 * 432];
        // PRIVMX_DEBUG("RTCVideoRenderer", "OnFrame", "Frame size: "+std::to_string(w) +"-"+std::to_string(h))
        frame->ConvertToRGBA((uint8_t*)pixels, 4, 768, 432);
        SDL_UpdateTexture(texture, NULL, pixels, 768 * sizeof(uint32_t));
        SDL_RenderClear(renderer); SDL_RenderCopy(renderer, texture, NULL, NULL); SDL_RenderPresent(renderer);
        delete pixels;
        
    }
private:
    void windowEventsLoop() {
        eventThreadLoop = std::make_shared<std::thread>([&](){
            while(true) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                SDL_Event event;
                while (SDL_PollEvent(&event)) {
                    if (event.type == SDL_QUIT) exit(0);
                    if (event.type == SDL_WINDOWEVENT) {
                        if (event.window.event == SDL_WINDOWEVENT_CLOSE)
                        {
                            exit(1);
                        }
                    }
                }
            }
        });
    }
    SDL_Window* window;
    SDL_Texture* texture;
    SDL_Renderer* renderer = NULL;
    std::string title;
    std::shared_ptr<std::thread> eventThreadLoop;
};

static vector<string_view> getParamsList(int argc, char* argv[]) {
    vector<string_view> args(argv + 1, argv + argc);
    return args;
}

class OnTrackImpl : public stream::OnTrackInterface {
public:
    OnTrackImpl() : _renderer(RTCVideoRendererImpl("Remote")) {}
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
            // LOG_INFO("VideoData[w-h]: ", videoData->w, "-", videoData->h);
            _renderer.OnFrame(videoData->w, videoData->h, videoData->frameData, "test");
        }
        if(data->type == stream::DataType::AUDIO) {
            auto audioData = std::dynamic_pointer_cast<stream::AudioData>(data);
            // LOG_INFO("AudioData[w-h]");
        }
    }
private:
    RTCVideoRendererImpl _renderer;
};

int main(int argc, char** argv) {
    auto params = getParamsList(argc, argv);
    if(params.size() != 5) {
        std::cout << "Invalid params required params are 'PrivKey', 'SolutionId', 'BridgeUrl', 'ContextId', 'StreamRoomId'" << std::endl;
        return -1;
    }
    std::string privKey = {params[0].begin(),  params[0].end()};
    std::string solutionId = {params[1].begin(),  params[1].end()};
    std::string bridgeUrl = {params[2].begin(),  params[2].end()};
    std::string contextId = {params[3].begin(),  params[3].end()};
    std::string streamRoomId = {params[4].begin(),  params[4].end()};
    try {
        core::Connection connection = core::Connection::connect(
            privKey, 
            solutionId, 
            bridgeUrl
        );    
        event::EventApi eventApi = event::EventApi::create(connection);
        stream::StreamApi streamApi = stream::StreamApi::create(connection, eventApi);
        core::EventQueue eventQueue = core::EventQueue::getInstance();
        auto onTrack = std::make_shared<OnTrackImpl>();
        streamApi.setOnTrackInterface(onTrack);
        stream::StreamSettings ssettings {};
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
            for(auto stream : streamlist) {
                std::cout << "stream:" <<  stream.id << std::endl;
                for(auto track : stream.tracks) {
                    streamsId.push_back(stream::StreamSubscription{stream.id, track.mid});
                }
                break;
            }
        }
        streamApi.joinStreamRoom(streamRoomId);
        streamApi.subscribeToRemoteStreams(streamRoomId, streamsId, ssettings);

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
                        streamApi.modifyRemoteStreamsSubscriptions(streamRoomId, toAddstreamsId, toRemovestreamsId, ssettings);
                    }
                }
            }
        });
        
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }

        streamApi.unsubscribeFromRemoteStreams(streamRoomId, streamsId);
        std::this_thread::sleep_for(std::chrono::seconds(5));
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


