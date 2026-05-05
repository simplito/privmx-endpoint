/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_REQUESTAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_REQUESTAPI_HPP_

#include <string>
#include <Poco/Dynamic/Var.h>

#include <privmx/privfs/gateway/RpcGateway.hpp>

#include "privmx/endpoint/store/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class RequestApi
{
public:
    RequestApi(privmx::privfs::RpcGateway::Ptr gateway);
    server::CreateRequestResult_c_struct createRequest(const server::CreateRequestModel_c_struct& model);
    void sendChunk(const server::ChunkModel_c_struct& model);
    void commitFile(const server::CommitFileModel_c_struct& model);

private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params);
    void requestVoid(const std::string& method, Poco::JSON::Object::Ptr params);

    privfs::RpcGateway::Ptr _gateway;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_REQUESTAPI_HPP_
