/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILEDATAPROVIDER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILEDATAPROVIDER_HPP_

#include "privmx/endpoint/store/ServerApi.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class FileDataProvider {
public:
    FileDataProvider(const std::shared_ptr<ServerApi>& serverApi) : _server(serverApi) {}
    virtual ~FileDataProvider() = default;
    virtual server::StoreFileReadResult getFileData(const server::StoreFileReadModel& model);
private:
    std::shared_ptr<ServerApi> _server;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILEDATAPROVIDER_HPP_
