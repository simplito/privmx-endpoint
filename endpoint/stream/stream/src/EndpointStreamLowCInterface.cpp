/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <functional>
#include <string>
#include <unordered_map>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>
#include <Pson/BinaryString.hpp>

#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/stream/cinterface/streamlow.h"
#include <privmx/endpoint/core/cinterface/CApiExecutor.hpp>
#include <privmx/endpoint/core/cinterface/InterfaceException.hpp>
#include <privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp>
#include "privmx/endpoint/stream/varinterface/StreamApiLowVarInterface.hpp"
#include "privmx/endpoint/event/varinterface/EventApiVarInterface.hpp"
#include "privmx/endpoint/stream/ProxyWebRTC.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::cinterface;

int privmx_endpoint_newStreamApiLow(Connection* connectionPtr, EventApi* eventApiPtr, StreamApiLow** outPtr) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    event::EventApiVarInterface* _eventApiPtr = (event::EventApiVarInterface*)eventApiPtr;
    stream::StreamApiLowVarInterface* ptr = new stream::StreamApiLowVarInterface(_connectionPtr->getApi(), _eventApiPtr->getApi(), core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (StreamApiLow*)ptr;
    return 1;
}

int privmx_endpoint_freeStreamApiLow(StreamApiLow* ptr) {
    delete (stream::StreamApiLowVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execStreamApiLow(StreamApiLow* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&]{
        stream::StreamApiLowVarInterface* _ptr = (stream::StreamApiLowVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((stream::StreamApiLowVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_stream_newProxyWebRTC(
    void* ctx,
    CreateOfferAndSetLocalDescriptionCallback callback1,
    CreateAnswerAndSetDescriptionsCallback  callback2,
    SetAnswerAndSetRemoteDescriptionCallback callback3,
    UpdateSessionIdCallback callback4,
    CloseCallback callback5,
    UpdateKeysCallback callback6,
    privmx_endpoint_stream_ProxyWebRTC** outPtr
) {
    *outPtr = (privmx_endpoint_stream_ProxyWebRTC*)new std::shared_ptr<stream::ProxyWebRTC>(
        std::make_shared<stream::ProxyWebRTC>(
            ctx,
            callback1,
            callback2,
            callback3,
            callback4,
            callback5,
            callback6));
    return 1;
}

int privmx_endpoint_stream_freeProxyWebRTC(privmx_endpoint_stream_ProxyWebRTC* ptr) {
    delete (std::shared_ptr<stream::ProxyWebRTC>*)ptr;
    return 1;
}
