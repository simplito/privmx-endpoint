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

#include "privmx/endpoint/kvdb/ServerTypes.hpp"
#include <Poco/Dynamic/Var.h>
#include <privmx/endpoint/core/ServerTypes.hpp>
#include <privmx/privfs/gateway/RpcGateway.hpp>
#include <string>

namespace privmx {
namespace endpoint {
namespace kvdb {

class ServerApi {
public:
    using Ptr = Poco::SharedPtr<ServerApi>;

    ServerApi(privmx::privfs::RpcGateway::Ptr gateway);

    server::KvdbCreateResult kvdbCreate(server::KvdbCreateModel model);
    void kvdbUpdate(server::KvdbUpdateModel model);
    void kvdbDelete(server::KvdbDeleteModel model);
    server::KvdbDeleteManyResult kvdbDeleteMany(server::KvdbDeleteManyModel model);
    server::KvdbGetResult kvdbGet(server::KvdbGetModel model);
    server::KvdbListResult kvdbList(server::KvdbListModel model);
    server::KvdbEntryGetResult kvdbEntryGet(server::KvdbEntryGetModel model);
    void kvdbEntrySet(server::KvdbEntrySetModel model);
    void kvdbEntryDelete(server::KvdbEntryDeleteModel model);
    server::KvdbListKeysResult kvdbListKeys(server::KvdbListKeysModel model);
    server::KvdbListEntriesResult kvdbListEntries(server::KvdbListEntriesModel model);
    server::KvdbEntryDeleteManyResult kvdbEntryDeleteMany(server::KvdbEntryDeleteManyModel model);

private:
    template<typename T>
    T request(const std::string& method, Poco::JSON::Object::Ptr params);
    Poco::Dynamic::Var request(const std::string& method, Poco::JSON::Object::Ptr params);

    privfs::RpcGateway::Ptr _gateway;
};

} // namespace kvdb
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_KVDB_SERVER_API_HPP_
