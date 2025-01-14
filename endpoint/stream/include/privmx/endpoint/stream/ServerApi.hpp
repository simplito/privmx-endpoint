/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_SERVER_API_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_SERVER_API_HPP_

#include <string>
#include <Poco/Dynamic/Var.h>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include "privmx/endpoint/stream/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class ServerApi {
public:
    using Ptr = Poco::SharedPtr<ServerApi>;

    ServerApi(privmx::privfs::RpcGateway::Ptr gateway);

    // server::StreamRoomCreateResult streamRoomCreate(server::StreamRoomCreateModel model);
    // void streamRoomUpdate(server::StreamRoomUpdateModel model);
    // server::StreamRoomListResult streamRoomList(server::StreamRoomListModel model);
    // server::StreamRoomGetResult streamRoomGet(server::StreamRoomGetModel model);
    // void streamRoomDelete(server::StreamRoomDeleteModel model);
    server::StreamGetTurnCredentialsResult streamGetTurnCredentials(server::StreamGetTurnCredentialsModel model);
    // server::StreamCreateResult streamCreate(server::StreamCreateModel model);
    // void streamUpdate(server::StreamUpdateModel model);
    server::StreamListResult streamList(server::StreamListModel model);
    // server::StreamGetResult streamGet(server::StreamGetModel model);
    // void streamDelete(server::StreamDeleteModel model);
    // server::StreamTrackAddResult streamTrackAdd(server::StreamTrackAddModel model);
    // void streamTrackRemove(server::StreamTrackRemoveModel model);
    // server::StreamTrackListResult streamTrackList(server::StreamTrackListModel model);
    // void streamTrackSendData(server::StreamTrackSendDataModel model);
    server::StreamPublishResult streamPublish(server::StreamPublishModel model);
    // Poco::Dynamic::Var streamUnpublish(server::StreamUnpublishModel model); // ???
    server::StreamJoinResult streamJoin(server::StreamJoinModel model);
    void streamAcceptOffer(server::StreamAcceptOfferModel model);
    // void streamLeave(server::StreamLeaveModel model);
    // TO DO
    void streamBroadcastNewKey(server::StreamBroadcastNewKey model);

private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params); //only typed object
    Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params); //Var
    template<typename T>
    T requestWS(const std::string& method, Poco::JSON::Object::Ptr params); //only typed object using websocket
    Poco::Dynamic::Var requestWS(const std::string& method, Poco::JSON::Object::Ptr params); //Var using websocket

    privfs::RpcGateway::Ptr _gateway;
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_SERVER_API_HPP_
