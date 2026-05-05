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

    server::StreamRoomCreateResult_c_struct streamRoomCreate(server::StreamRoomCreateModel_c_struct model);
    void streamRoomUpdate(server::StreamRoomUpdateModel_c_struct model);
    server::StreamRoomListResult_c_struct streamRoomList(server::StreamRoomListModel_c_struct model);
    server::StreamRoomGetResult_c_struct streamRoomGet(server::StreamRoomGetModel_c_struct model);
    void streamRoomDelete(server::StreamRoomDeleteModel_c_struct model);
    server::StreamGetTurnCredentialsResult_c_struct streamGetTurnCredentials();
    server::StreamListResult_c_struct streamList(server::StreamListModel_c_struct model);
    server::StreamPublishResult_c_struct streamPublish(server::StreamPublishModel_c_struct model);
    server::StreamPublishResult_c_struct streamUpdate(server::StreamUpdateModel_c_struct model);

    void streamAcceptOffer(server::StreamAcceptOfferModel_c_struct model);
    void streamSetNewOffer(server::StreamSetNewOfferModel_c_struct model);

    void streamRoomSendCustomEvent(server::StreamRoomSendCustomEventModel_c_struct model);
    void streamUnpublish(server::StreamUnpublishModel_c_struct model);

    server::StreamsSubscribeResult_c_struct streamsSubscribeToRemote(server::StreamsSubscribeModel_c_struct model);
    server::StreamsSubscribeResult_c_struct streamsModifyRemoteSubscriptions(server::StreamsModifySubscriptionsModel_c_struct model);
    server::StreamsSubscribeResult_c_struct streamsUnsubscribeFromRemote(server::StreamsUnsubscribeModel_c_struct model);
    void streamRoomJoin(server::StreamRoomJoinModel_c_struct model);
    void streamRoomLeave(server::StreamRoomLeaveModel_c_struct model);
    void streamRoomEnableRecording(server::StreamRoomRecordingModel_c_struct model);

    void trickle(server::StreamTrickleModel_c_struct model);
    bool isConnected() {return _gateway ? _gateway->isConnected() : false;}
private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params);
    Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params);
    template<typename T>
    T requestWS(const std::string& method, Poco::JSON::Object::Ptr params);
    Poco::Dynamic::Var requestWS(const std::string& method, Poco::JSON::Object::Ptr params);

    privfs::RpcGateway::Ptr _gateway;
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_SERVER_API_HPP_
