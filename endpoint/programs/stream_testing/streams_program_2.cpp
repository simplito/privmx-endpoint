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

int main(int argc, char** argv) {

    auto params = getParamsList(argc, argv);

    try {
        crypto::CryptoApi cryptoApi = crypto::CryptoApi::create();
        core::Connection connection = core::Connection::connect("L3DdgfGagr2yGFEHs1FcRQRGrpa4nwQKdPcfPiHxcDcZeEb3wYaN", "fc47c4e4-e1dc-414a-afa4-71d436398cfc", "http://webrtc2.s24.simplito.com:3000");
        stream::StreamApi streamApi = stream::StreamApi::create(connection);
        
        auto context = connection.listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0];
        auto streamList = streamApi.listStreamRooms(context.contextId, {.skip=0, .limit=1, .sortOrder="asc"});
        auto pubKey = cryptoApi.derivePublicKey("L3DdgfGagr2yGFEHs1FcRQRGrpa4nwQKdPcfPiHxcDcZeEb3wYaN");
        std::vector<privmx::endpoint::core::UserWithPubKey> users = {
            privmx::endpoint::core::UserWithPubKey{.userId=context.userId, .pubKey=pubKey}
        };
        std::string streamRoomId = streamApi.createStreamRoom(
            context.contextId,
            users,
            users,
            privmx::endpoint::core::Buffer::from(""),
            privmx::endpoint::core::Buffer::from(""),
            std::nullopt
        );
        for(int ii = 0; ii<1 ; ii++) {
            auto streamId_1 = streamApi.createStream(streamRoomId);
            auto listAudioRecordingDevices = streamApi.listAudioRecordingDevices();
            streamApi.trackAdd(streamId_1, stream::DeviceType::Audio);
            // auto listVideoRecordingDevices = streamApi.listVideoRecordingDevices();
            // streamApi.trackAdd(streamId_1, stream::DeviceType::Video);
            streamApi.publishStream(streamId_1);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            auto streamlist = streamApi.listStreams(streamRoomId);
            std::vector<int64_t> streamsId;
            for(int i = 0; i < streamlist.size(); i++) {
                streamsId.push_back(streamlist[i].streamId);
            }
            // {
            //     stream::streamJoinSettings ssettings;
            //     auto streamId_2 = streamApi.joinStream(streamRoomId, streamsId, ssettings);

            //     std::this_thread::sleep_for(std::chrono::seconds(120));
            //     streamApi.unpublishStream(streamId_1);
            //     streamApi.leaveStream(streamId_2);
            //     std::this_thread::sleep_for(std::chrono::seconds(4));
            // }
            {
                stream::streamJoinSettings ssettings;
                for(int i = 0; i < 20; i++) {
                    auto tmp = streamApi.joinStream(streamRoomId, streamsId, ssettings);
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    streamApi.leaveStream(tmp);
                }
                streamApi.unpublishStream(streamId_1);
            }
        }
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


