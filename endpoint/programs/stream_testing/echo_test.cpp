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
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/utils/PrivmxException.hpp>

using namespace std;
using namespace privmx::endpoint;

class OnTrackImpl : public stream::OnTrackInterface {
public:
    OnTrackImpl() = default;
    virtual void OnRemoteTrack(stream::Track tack, stream::TrackAction action) override {}
    virtual void OnData(std::shared_ptr<stream::Data> data) override {}
};

static vector<string_view> getParamsList(int argc, char* argv[]) {
    vector<string_view> args(argv + 1, argv + argc);
    return args;
}

int main(int argc, char** argv) {
    auto params = getParamsList(argc, argv);
    if(params.size() != 4) {
        std::cout << "Invalid params. Required params are: 'PrivKey', 'SolutionId', 'BridgeUrl', 'ContextId'" << std::endl;
        return -1;
    }
    std::string privKey = {params[0].begin(),  params[0].end()};
    std::string solutionId = {params[1].begin(),  params[1].end()};
    std::string bridgeUrl = {params[2].begin(),  params[2].end()};
    std::string contextId = {params[3].begin(),  params[3].end()};
    try {
        core::Connection connection = core::Connection::connect(
            privKey, 
            solutionId, 
            bridgeUrl
        );
        stream::StreamApi streamApi = stream::StreamApi::create(connection);
        std::string streamRoomId;
        auto contextUsersInfo = connection.listContextUsers(contextId, {0, 100, "asc"});
        std::vector<core::UserWithPubKey> usersWithPubKey = {};
        for(const auto& userInfo : contextUsersInfo.readItems) {
            usersWithPubKey.push_back(userInfo.user);
        }
        streamRoomId = streamApi.createStreamRoom(contextId, usersWithPubKey, usersWithPubKey, core::Buffer::from(""), core::Buffer::from(""), std::nullopt);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        streamApi.joinStreamRoom(streamRoomId);
        auto streamId_1 = streamApi.createStream(streamRoomId);
        auto mediaDevices = streamApi.getAudioDevices();
        for(const auto& mediaDevice: mediaDevices) {
            if(mediaDevice.type == stream::DeviceType::Audio) {
                streamApi.addTrack(streamId_1, mediaDevice, {});
                break;
            }
        }
        
        streamApi.publishStream(streamId_1);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto streamlist = streamApi.listStreams(streamRoomId);
        std::vector<stream::StreamSubscription> streamsId;
        auto onTrack = std::make_shared<OnTrackImpl>();
        for(int i = 0; i < streamlist.size(); i++) {
            streamsId.push_back(stream::StreamSubscription{streamlist[i].id, std::nullopt});
        }
        streamApi.subscribeToRemoteStreams(streamRoomId, streamsId);
        std::this_thread::sleep_for(std::chrono::seconds(60));

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


