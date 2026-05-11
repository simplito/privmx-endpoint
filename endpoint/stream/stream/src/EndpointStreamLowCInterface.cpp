/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>
#include <Poco/Dynamic/Var.h>

#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/stream/cinterface/streamlow.h"
#include <privmx/endpoint/core/cinterface/CApiExecutor.hpp>
#include <privmx/endpoint/core/cinterface/InterfaceException.hpp>
#include <privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp>
#include "privmx/endpoint/stream/varinterface/StreamApiLowVarInterface.hpp"
#include "privmx/endpoint/stream/ProxyWebRTC.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::cinterface;

int privmx_endpoint_newStreamApiLow(Connection* connectionPtr, StreamApiLow** outPtr) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    stream::StreamApiLowVarInterface* ptr = new stream::StreamApiLowVarInterface(_connectionPtr->getApi(), core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
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

int privmx_endpoint_stream_extractKey(const privmx_endpoint_stream_Key keys[], size_t index, const char** keyId, const unsigned char** keyBuf, size_t* keySize, privmx_endpoint_stream_KeyType* type) {
    const auto& key = keys[index];
    *keyId = key.keyId;
    *keyBuf = key.key;
    *keySize = key.keySize;
    *type = key.type;
    return 1;
}

int privmx_endpoint_stream_newProxyWebRTC(
    privmx_endpoint_stream_WebRTCInterface webRTCInterface,
    privmx_endpoint_stream_ProxyWebRTC** outPtr
) {
    *outPtr = (privmx_endpoint_stream_ProxyWebRTC*)new std::shared_ptr<stream::ProxyWebRTC>(
        std::make_shared<stream::ProxyWebRTC>(webRTCInterface));
    return 1;
}

int privmx_endpoint_stream_freeProxyWebRTC(privmx_endpoint_stream_ProxyWebRTC* ptr) {
    delete (std::shared_ptr<stream::ProxyWebRTC>*)ptr;
    return 1;
}
