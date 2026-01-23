#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/Config.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/stream/Types.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/Debug.hpp>
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
        // std::cout << w << " - " << h << " frame Size" << std::endl;
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
        streamApi.joinStreamRoom(streamRoomId);
        auto streamHandle = streamApi.createStream(streamRoomId);
        auto mediaDevices = streamApi.getMediaDevices();
        for(const auto& mediaDevice: mediaDevices) {
            if(mediaDevice.type == stream::DeviceType::Audio) {
                streamApi.addTrack(streamHandle, mediaDevice);
                break;
            }
        }
        for(const auto& mediaDevice: mediaDevices) {
            if(mediaDevice.type == stream::DeviceType::Video) {
                streamApi.addTrack(streamHandle, mediaDevice);
                break;
            }
        }
        streamApi.publishStream(streamHandle);
        while (true) {std::this_thread::sleep_for(std::chrono::seconds(5));}
        
        streamApi.unpublishStream(streamHandle);
        connection.disconnect();
        std::this_thread::sleep_for(std::chrono::seconds(5));

       
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


