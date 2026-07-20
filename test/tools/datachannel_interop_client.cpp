#include <chrono>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/stream/StreamApiImpl.hpp>

// Live E2E DataChannel interop client, room must be created
// test and either sends or receives one
//
// Usage:
//   datachannel_interop_client <privKey> <solutionId> <bridgeUrl> <contextId> \
//       <streamRoomId> send <message>
//   datachannel_interop_client <privKey> <solutionId> <bridgeUrl> <contextId> \
//       <streamRoomId> recv
//
// Synchronization with the caller is done over stdout/stdin (line-buffered):
//   send: prints "PUBLISHED", then blocks reading one line from stdin (the caller
//         writes it once its subscriber is set up) before calling sendData and
//         printing "SENT".
//   recv: prints "READY" once subscribed, then prints one "RECV seq=<n>
//         status=<n> data=<text>" line per plain-data message received.

using namespace privmx::endpoint;

namespace {

class DataListener : public stream::OnTrackInterface {
public:
    void OnRemoteTrack(stream::Track, stream::TrackAction) override {}

    void OnData(std::shared_ptr<stream::Data> data) override {
        if (data->type != stream::DataType::PLAIN) return;
        auto plain = std::static_pointer_cast<stream::PlainData>(data);
        std::cout << "RECV seq=" << plain->seq << " status=" << plain->statusCode
                   << " data=" << plain->data.stdString() << std::endl;
    }
};

std::vector<std::string_view> getParamsList(int argc, char* argv[]) {
    return std::vector<std::string_view>(argv + 1, argv + argc);
}

void printUsage() {
    std::cerr << "Usage:\n"
                 "  datachannel_interop_client <privKey> <solutionId> <bridgeUrl> <contextId> "
                 "<streamRoomId> send <message>\n"
                 "  datachannel_interop_client <privKey> <solutionId> <bridgeUrl> <contextId> "
                 "<streamRoomId> recv\n";
}

} // namespace

int main(int argc, char** argv) {
    auto params = getParamsList(argc, argv);
    if (params.size() < 6) {
        printUsage();
        return 2;
    }

    std::string privKey(params[0]);
    std::string solutionId(params[1]);
    std::string bridgeUrl(params[2]);
    std::string contextId(params[3]);
    std::string streamRoomId(params[4]);
    std::string mode(params[5]);
    (void)contextId; // the room already exists; contextId is accepted for symmetry/logging only.

    try {
        auto connection = core::Connection::connect(privKey, solutionId, bridgeUrl);
        auto eventApi = event::EventApi::create(connection);
        auto streamApi = stream::StreamApi::create(connection, eventApi);

        if (mode == "send") {
            if (params.size() < 7) {
                printUsage();
                return 2;
            }
            std::string message(params[6]);

            streamApi.joinStreamRoom(streamRoomId);
            auto handle = streamApi.createStream(streamRoomId);
            streamApi.getImpl()->addTrack(
                handle, {"", "", stream::DeviceType::Plain}, stream::MediaTrackConstrains{}
            );
            streamApi.publishStream(handle);
            std::this_thread::sleep_for(std::chrono::milliseconds(1500)); // let publish propagate server-side

            std::cout << "PUBLISHED" << std::endl;
            std::string line;
            std::getline(std::cin, line); // wait for the caller's subscriber to be ready

            streamApi.sendData(handle, core::Buffer::from(message));
            std::this_thread::sleep_for(std::chrono::milliseconds(500)); // let the send flush
            std::cout << "SENT" << std::endl;
            return 0;
        }

        if (mode == "recv") {
            streamApi.joinStreamRoom(streamRoomId);
            auto listener = std::make_shared<DataListener>();
            streamApi.addRemoteStreamListener(streamRoomId, std::nullopt, listener);

            auto streams = streamApi.listStreams(streamRoomId);
            std::vector<stream::StreamSubscription> subscriptions;
            for (const auto& s : streams) {
                subscriptions.push_back(stream::StreamSubscription{s.id, std::nullopt});
            }
            streamApi.createSubscriberStream(streamRoomId, subscriptions);

            std::cout << "READY" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(15));
            return 0;
        }

        std::cerr << "Unknown mode: " << mode << std::endl;
        printUsage();
        return 2;
    } catch (const core::Exception& e) {
        std::cerr << "ERROR: " << e.getFull() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
}
