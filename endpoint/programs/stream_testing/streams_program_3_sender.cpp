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
    if(params.size() != 5) {
        std::cout << "Invalid params required params are 'PrivKey', 'SolutionId', 'BridgeUrl', 'ContextId', 'StreamRoomId'" << std::endl;
        return -1;
    }
    std::string privKey = {params[0].begin(),  params[0].end()};
    std::string solutionId = {params[1].begin(),  params[1].end()};
    std::string bridgeUrl = {params[2].begin(),  params[2].end()};
    std::string contextId = {params[3].begin(),  params[3].end()};
    std::string streamRoomId = {params[4].begin(),  params[4].end()};
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

        streamApi.subscribeFor({
            streamApi.buildSubscriptionQuery(stream::EventType::STREAMROOM_UPDATE, stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAMROOM_DELETE, stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_PUBLISH,    stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_UNPUBLISH,  stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_JOIN,       stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
            streamApi.buildSubscriptionQuery(stream::EventType::STREAM_LEAVE,      stream::EventSelectorType::STREAMROOM_ID, streamRoomId),
        });

        streamApi.joinStreamRoom(streamRoomId);
        // for(int j = 0; j < 5; j++) {
        // streamApi.joinStreamRoom(streamRoomId);

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
        // for(const auto& mediaDevice: mediaDevices) {
        //     if(mediaDevice.type == stream::DeviceType::Desktop) {
        //         streamApi.addTrack(streamHandle, mediaDevice);
        //         break;
        //     }
        // }
        streamApi.publishStream(streamHandle);
        
        int i = 20;
        while (i--) {
            // std::this_thread::sleep_for(std::chrono::seconds(10));
            // std::cout << "-------------------------------------------------------------------------------------------------------" << std::endl;
            // for(const auto& mediaDevice: mediaDevices) {
            //     if(mediaDevice.type == stream::DeviceType::Video) {
            //         streamApi.removeTrack(streamHandle, mediaDevice);
            //         break;
            //     }
            // }
            // std::this_thread::sleep_for(std::chrono::seconds(5));
            // std::cout << "----------------------------------------------remove track---------------------------------------------" << std::endl;
            // core::VarSerializer serializer = core::VarSerializer(core::VarSerializer::Options{false, core::VarSerializer::Options::STD_STRING});
            // streamApi.updateStream(streamHandle);
            // std::cout << "----------------------------------------------streams list---------------------------------------------" << std::endl;
            // auto streamsList = streamApi.listStreams(streamRoomId);
            // std::cout << privmx::utils::Utils::stringifyVar(serializer.serialize(streamsList), true) << std::endl;
            // std::cout << "-------------------------------------------------------------------------------------------------------" << std::endl;
            // auto mediaDevices = streamApi.getMediaDevices();
            // for(const auto& mediaDevice: mediaDevices) {
            //     if(mediaDevice.type == stream::DeviceType::Video) {
            //         streamApi.addTrack(streamHandle, mediaDevice);
            //         break;
            //     }
            // }
            // std::this_thread::sleep_for(std::chrono::seconds(5));
            // std::cout << "----------------------------------------------add track------------------------------------------------" << std::endl;
            
            // streamApi.updateStream(streamHandle);
        };
        std::this_thread::sleep_for(std::chrono::seconds(600));
        streamApi.unpublishStream(streamHandle);
        // streamApi.leaveStreamRoom(streamRoomId);

        std::this_thread::sleep_for(std::chrono::seconds(2));
        // }



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


