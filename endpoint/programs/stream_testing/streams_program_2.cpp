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
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/utils/PrivmxException.hpp>

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
    try {
        core::Connection connection = core::Connection::connect(
            privKey, 
            solutionId, 
            bridgeUrl
        );    
        event::EventApi eventApi = event::EventApi::create(connection);
        stream::StreamApi streamApi = stream::StreamApi::create(connection, eventApi);
        streamApi.joinRoom(streamRoomId);
        auto streamId_1 = streamApi.createStream(streamRoomId);
        auto mediaDevices = streamApi.getMediaDevices();
        for(const auto& mediaDevice: mediaDevices) {
            if(mediaDevice.type == stream::DeviceType::Audio) {
                streamApi.addTrack(streamId_1, mediaDevice);
                break;
            }
        }
        
        streamApi.publishStream(streamId_1);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto streamlist = streamApi.listStreams(streamRoomId);
        std::vector<int64_t> streamsId;
        for(int i = 0; i < streamlist.size(); i++) {
            streamsId.push_back(streamlist[i].streamId);
        }
        stream::StreamSettings ssettings;
        streamApi.subscribeToRemoteStreams(streamRoomId, streamsId, ssettings);

        std::this_thread::sleep_for(std::chrono::seconds(120));
        streamApi.unpublishStream(streamId_1);
        streamApi.unsubscribeFromRemoteStreams(streamRoomId, streamsId);
        streamApi.leaveRoom(streamRoomId);
        std::this_thread::sleep_for(std::chrono::seconds(1));

       
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


