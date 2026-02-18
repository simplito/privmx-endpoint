#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <thread>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/Config.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/stream/StreamVarSerializer.hpp>
#include <privmx/endpoint/stream/Types.hpp>
#include <privmx/endpoint/stream/webrtc/Types.hpp>
#include <privmx/endpoint/stream/webrtc/OnTrackInterface.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/Logger.hpp>

using namespace std;
using namespace privmx::endpoint;

static vector<string_view> getParamsList(int argc, char* argv[]) {
    vector<string_view> args(argv + 1, argv + argc);
    return args;
}

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
    atomic_bool stop = false;
    core::EventQueue eventQueue = core::EventQueue::getInstance();
    std::thread eventThread;
    try {
        core::Connection connection = core::Connection::connect(
            privKey, 
            solutionId, 
            bridgeUrl
        );        
        eventThread = std::thread([&](){
            while (!stop) {
                auto eventHolder = eventQueue.waitEvent();
            }
        });
        event::EventApi eventApi = event::EventApi::create(connection);
        stream::StreamApi streamApi = stream::StreamApi::create(connection, eventApi);
        std::string streamRoomId;
        if(streamRoomIdOpt.has_value()) {
            streamRoomId = streamRoomIdOpt.has_value();
        } else {
            auto listStreamRoom = streamApi.listStreamRooms(contextId, {.skip=0, .limit=100, .sortOrder="asc"});
            for(const auto& streamRoom: listStreamRoom.readItems){
                streamApi.deleteStreamRoom(streamRoom.streamRoomId);
            }

            auto contextUsersInfo = connection.listContextUsers(contextId, {0, 100, "asc"});
            std::vector<core::UserWithPubKey> usersWithPubKey = {};
            for(const auto& userInfo : contextUsersInfo.readItems) {
                usersWithPubKey.push_back(userInfo.user);
            }
            streamRoomId = streamApi.createStreamRoom(contextId, usersWithPubKey, usersWithPubKey, core::Buffer::from(""), core::Buffer::from(""), std::nullopt);
            std::cout << "===============================================================================================" << endl;
            std::cout << "new streamRoomId: " << streamRoomId << endl;
            std::cout << "===============================================================================================" << endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }

        streamApi.subscribeFor({
            streamApi.buildSubscriptionQuery(stream::EventType::STREAMROOM_UPDATE, stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAMROOM_DELETE, stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_PUBLISH,    stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_UNPUBLISH,  stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_JOIN,       stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_LEAVE,      stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
        });

        streamApi.joinStreamRoom(streamRoomId);
        auto streamHandle = streamApi.createStream(streamRoomId);
        
        auto audioDevices = streamApi.getAudioDevices();
        for(const auto& audioDevice: audioDevices) {
            streamApi.addTrack(streamHandle, audioDevice, stream::MediaTrackConstrains{});
            break;
        }
        auto videoDevices = streamApi.getVideoDevices();
        for(const auto& videoDevice: videoDevices) {
            streamApi.addTrack(streamHandle, videoDevice, stream::MediaTrackConstrains{.idealWidth=1280, .idealHeight=720, .idealFps=1});
            break;
        }

        // auto desktopDevices = streamApi.getDesktopDevices(stream::DesktopType::Screen);
        // for(const auto& desktopDevice: desktopDevices) {
        //     streamApi.addTrack(streamHandle, desktopDevice, stream::MediaTrackConstrains{.idealFps=1});
        //     break;
        // }

        streamApi.publishStream(streamHandle);
        std::this_thread::sleep_for(std::chrono::seconds(600));
        streamApi.unpublishStream(streamHandle);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        streamApi.leaveStreamRoom(streamRoomId);
        connection.disconnect();
        stop = true;
        eventQueue.emitBreakEvent();
        eventThread.join();
        std::this_thread::sleep_for(std::chrono::seconds(5));

       
    } catch (const core::Exception& e) {
        cerr << e.getFull() << endl;
        stop = true;
        if(eventThread.joinable()) {eventQueue.emitBreakEvent(); eventThread.join();}
    } catch (const privmx::utils::PrivmxException& e) {
        cerr << e.what() << endl;
        cerr << e.getData() << endl;
        cerr << e.getCode() << endl;
        stop = true;
        if(eventThread.joinable()) {eventQueue.emitBreakEvent(); eventThread.join();}
    } catch (const exception& e) {
        cerr << e.what() << endl;
        stop = true;
        if(eventThread.joinable()) {eventQueue.emitBreakEvent(); eventThread.join();}
    } catch (...) {
        cerr << "Error" << endl;
        stop = true;
        if(eventThread.joinable()) {eventQueue.emitBreakEvent(); eventThread.join();}
    }

    return 0;
}


