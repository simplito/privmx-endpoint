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

    server::StreamRoomCreateResult streamRoomCreate(server::StreamRoomCreateModel model);
    void streamRoomUpdate(server::StreamRoomUpdateModel model);
    server::StreamRoomListResult streamRoomList(server::StreamRoomListModel model);
    server::StreamRoomGetResult streamRoomGet(server::StreamRoomGetModel model);
    void streamRoomDelete(server::StreamRoomDeleteModel model);
    server::StreamGetTurnCredentialsResult streamGetTurnCredentials(server::StreamGetTurnCredentialsModel model);
    server::StreamListResult streamList(server::StreamListModel model);
    server::StreamPublishResult streamPublish(server::StreamPublishModel model);

    void streamAcceptOffer(server::StreamAcceptOfferModel model);
    void streamRoomSendCustomEvent(server::StreamRoomSendCustomEventModel model);
    void streamUnpublish(server::StreamUnpublishModel model);

    server::StreamsSubscribeResult streamsSubscribeToRemote(StreamsSubscribeModel model);
    server::StreamsSubscribeResult streamsModifyRemoteSubscriptions(StreamsModifySubscriptionsModel model);
    server::StreamsSubscribeResult streamsUnsubscribeFromRemote(StreamsUnsubscribeModel model);
    void streamRoomJoin(server::StreamJoinModel model);
    void streamRoomLeave(server::StreamLeaveModel model);

    void trickle(server::StreamTrickleModel model);

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
