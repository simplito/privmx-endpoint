/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

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
    server::StoreCreateResult_c_struct storeCreate(const server::StoreCreateModel_c_struct& model);
    void storeUpdate(const server::StoreUpdateModel_c_struct& model);
    void storeDelete(const server::StoreDeleteModel_c_struct& model);
    server::StoreGetResult_c_struct storeGet(const server::StoreGetModel_c_struct& model);
    server::StoreListResult_c_struct storeList(const server::StoreListModel_c_struct& model);
    server::StoreFileGetResult_c_struct storeFileGet(const server::StoreFileGetModel_c_struct& model);
    server::StoreFileGetManyResult_c_struct storeFileGetMany(const server::StoreFileGetManyModel_c_struct& model);
    server::StoreFileListResult_c_struct storeFileList(const server::StoreFileListModel_c_struct& model);
    server::StoreFileCreateResult_c_struct storeFileCreate(const server::StoreFileCreateModel_c_struct& model);
    server::StoreFileReadResult_c_struct storeFileRead(const server::StoreFileReadModel_c_struct& model);
    void storeFileWrite(const server::StoreFileWriteModel_c_struct& model);
    void storeFileWrite(const server::StoreFileWriteModelByOperations_c_struct& model);
    void storeFileUpdate(const server::StoreFileUpdateModel_c_struct& model);
    void storeFileDelete(const server::StoreFileDeleteModel_c_struct& model);
private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params);
    void requestVoid(const std::string& method, Poco::JSON::Object::Ptr params);

    privfs::RpcGateway::Ptr _gateway;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_SERVERAPI_HPP_
