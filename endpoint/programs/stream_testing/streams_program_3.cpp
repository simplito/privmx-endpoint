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
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/stream/Types.hpp>
#include <privmx/endpoint/crypto/CryptoApi.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <SDL2/SDL.h>

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


#include <nanogui/screen.h>
#include <nanogui/layout.h>
#include <nanogui/window.h>
#include <nanogui/button.h>
#include <nanogui/canvas.h>
#include <nanogui/shader.h>
#include <nanogui/texture.h>
#include <nanogui/renderpass.h>
#include <GLFW/glfw3.h>

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
                    std::cerr << "SDL_Event.type = " << event.type << std::endl;
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

int main(int argc, char** argv) {

    auto params = getParamsList(argc, argv);

    try {
        crypto::CryptoApi cryptoApi = crypto::CryptoApi::create();
        core::Connection connection = core::Connection::connect("L3DdgfGagr2yGFEHs1FcRQRGrpa4nwQKdPcfPiHxcDcZeEb3wYaN", "fc47c4e4-e1dc-414a-afa4-71d436398cfc", "http://webrtc2.s24.simplito.com:3000");        
        event::EventApi eventApi = event::EventApi::create(connection);
        stream::StreamApi streamApi = stream::StreamApi::create(connection, eventApi);
        
        core::Connection connection_patryk = core::Connection::connect("KxVnzhhH2zMpumuhzBRoAC6dv9a7pKEzoKuftjP5Vr4MGYoAbgn8", "fc47c4e4-e1dc-414a-afa4-71d436398cfc", "http://webrtc2.s24.simplito.com:3000");
        event::EventApi eventApi_patryk = event::EventApi::create(connection_patryk);
        stream::StreamApi streamApi_patryk = stream::StreamApi::create(connection_patryk, eventApi_patryk);
        
        auto context = connection.listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0];
        auto streamList = streamApi.listStreamRooms(context.contextId, {.skip=0, .limit=100, .sortOrder="asc"});
        std::string streamRoomId = "";
        std::vector<privmx::endpoint::core::UserWithPubKey> users = {
            privmx::endpoint::core::UserWithPubKey{.userId="patryk", .pubKey="51ciywf56WuDKxyEuquMsfoydEK2NavoFtFBvoKWEi7VuqHkur"},
            privmx::endpoint::core::UserWithPubKey{.userId="user1",  .pubKey="8RUGiizsLszXAfWXEaPxjrcnXCsgd48zCHmmK6ng2cZCquMoeZ"}
        };
        std::cout << cryptoApi.derivePublicKey("KxVnzhhH2zMpumuhzBRoAC6dv9a7pKEzoKuftjP5Vr4MGYoAbgn8") << std::endl;
        if(streamList.readItems.size() == 0) {
            streamRoomId = streamApi.createStreamRoom(
                context.contextId,
                users,
                users,
                privmx::endpoint::core::Buffer::from(""),
                privmx::endpoint::core::Buffer::from(""),
                std::nullopt
            );
        } else {
            streamRoomId = streamList.readItems[0].streamRoomId;
        }
        auto pubKey = cryptoApi.derivePublicKey("L3DdgfGagr2yGFEHs1FcRQRGrpa4nwQKdPcfPiHxcDcZeEb3wYaN");        
        streamApi.subscribeForStreamEvents();
        
        auto streamId = streamApi.createStream(streamRoomId);
        auto listAudioRecordingDevices = streamApi.listAudioRecordingDevices();
        streamApi.trackAdd(streamId, stream::TrackParam{{.id=0, .type=stream::DeviceType::Audio}, .params_JSON="{}"});
        auto listVideoRecordingDevices = streamApi.listVideoRecordingDevices();
        streamApi.trackAdd(streamId, stream::TrackParam{{.id=0, .type=stream::DeviceType::Video}, .params_JSON="{}"});
        streamApi.publishStream(streamId);
        while (true) {std::this_thread::sleep_for(std::chrono::seconds(5));}
        // std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Stream trackRemove~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
        // streamApi.trackRemove(streamId, stream::Track{.id=0, .type=stream::DeviceType::Video});
        // // std::this_thread::sleep_for(std::chrono::seconds(10));
        // // std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Stream trackAdd~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
        // // streamApi.trackAdd(streamId, stream::TrackParam{{.id=0, .type=stream::DeviceType::Video}, .params_JSON="{}"});
        
        // streamApi.reconfigureStream(streamId, "{}");
        // std::this_thread::sleep_for(std::chrono::seconds(20));
        
        std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Stream Reset done~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
        streamApi.unpublishStream(streamId);
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


