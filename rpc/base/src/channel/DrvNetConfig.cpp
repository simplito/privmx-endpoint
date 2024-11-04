/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/rpc/channel/DrvNetConfig.hpp"
#include "privmx/rpc/RpcConfig.hpp"
#include "privmx/rpc/RpcException.hpp"

#ifdef PRIVMX_ENABLE_NET_DRIVER
#include <privmx/drv/net.h>
#endif

using namespace privmx::rpc;

void DrvNetConfig::setConfig([[maybe_unused]] const std::string& config) {
#ifdef PRIVMX_ENABLE_NET_DRIVER
    int status = privmxDrvNet_setConfig(config.c_str());
    if (status != 0) {
        throw RpcException("privmxDrvNet_setConfig: " + std::to_string(status));
    }
#endif
}
