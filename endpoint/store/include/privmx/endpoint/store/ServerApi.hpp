#ifndef _PRIVMXLIB_ENDPOINT_STORE_SERVERAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_SERVERAPI_HPP_

#include <string>
#include <Poco/Dynamic/Var.h>

#include <privmx/privfs/gateway/RpcGateway.hpp>

#include "privmx/endpoint/store/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class ServerApi 
{
public:    
    ServerApi(const privmx::privfs::RpcGateway::Ptr& gateway);
    server::StoreCreateResult storeCreate(const server::StoreCreateModel& model);
    void storeUpdate(const server::StoreUpdateModel& model);
    void storeDelete(const server::StoreDeleteModel& model);
    server::StoreGetResult storeGet(const server::StoreGetModel& model);
    server::StoreListResult storeList(const server::StoreListModel& model);
    server::StoreFileGetResult storeFileGet(const server::StoreFileGetModel& model);
    server::StoreFileGetManyResult storeFileGetMany(const server::StoreFileGetManyModel& model);
    server::StoreFileListResult storeFileList(const server::StoreFileListModel& model);
    server::StoreFileCreateResult storeFileCreate(const server::StoreFileCreateModel& model);
    server::StoreFileReadResult storeFileRead(const server::StoreFileReadModel& model);
    void storeFileWrite(const server::StoreFileWriteModel& model);
    void storeFileUpdate(const server::StoreFileUpdateModel& model);
    void storeFileDelete(const server::StoreFileDeleteModel& model);    
private:
    template<typename T> 
    T request(const std::string& method, const Poco::JSON::Object::Ptr& params); //only typed object
    Poco::Dynamic::Var request(const std::string& method, const Poco::JSON::Object::Ptr& params); //Var

    privfs::RpcGateway::Ptr _gateway;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_SERVERAPI_HPP_
