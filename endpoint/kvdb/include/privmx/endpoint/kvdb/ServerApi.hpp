/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_KVDB_SERVER_API_HPP_
#define _PRIVMXLIB_ENDPOINT_KVDB_SERVER_API_HPP_

#include <string>
#include <Poco/Dynamic/Var.h>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include "privmx/endpoint/kvdb/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace kvdb {

class ServerApi {
public:
    using Ptr = Poco::SharedPtr<ServerApi>;

    ServerApi(privmx::privfs::RpcGateway::Ptr gateway);

    server::KvdbCreateResult_c_struct kvdbCreate(server::KvdbCreateModel_c_struct model);
    void kvdbUpdate(server::KvdbUpdateModel_c_struct model);
    void kvdbDelete(server::KvdbDeleteModel_c_struct model);
    server::KvdbDeleteManyResult_c_struct kvdbDeleteMany(server::KvdbDeleteManyModel_c_struct model);
    server::KvdbGetResult_c_struct kvdbGet(server::KvdbGetModel_c_struct model);
    server::KvdbListResult_c_struct kvdbList(server::KvdbListModel_c_struct model);
    server::KvdbEntryGetResult_c_struct kvdbEntryGet(server::KvdbEntryGetModel_c_struct model);
    void kvdbEntrySet(server::KvdbEntrySetModel_c_struct model);
    void kvdbEntryDelete(server::KvdbEntryDeleteModel_c_struct model);
    server::KvdbListKeysResult_c_struct kvdbListKeys(server::KvdbListKeysModel_c_struct model);
    server::KvdbListEntriesResult_c_struct kvdbListEntries(server::KvdbListEntriesModel_c_struct model);
    server::KvdbEntryDeleteManyResult_c_struct kvdbEntryDeleteMany(server::KvdbEntryDeleteManyModel_c_struct model);
private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params);
    Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params);

    privfs::RpcGateway::Ptr _gateway;
};

} // kvdb
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_SERVER_API_HPP_
