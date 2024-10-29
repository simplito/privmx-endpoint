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
    server::CreateRequestResult createRequest(const server::CreateRequestModel& model);
    void sendChunk(const server::ChunkModel& model);
    void commitFile(const server::CommitFileModel& model);
    
private:
    template<typename T> 
    T request(const std::string& method, const Poco::JSON::Object::Ptr& params); //only typed object
    Poco::Dynamic::Var request(const std::string& method, const Poco::JSON::Object::Ptr& params); //Var

    privfs::RpcGateway::Ptr _gateway;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_REQUESTAPI_HPP_
