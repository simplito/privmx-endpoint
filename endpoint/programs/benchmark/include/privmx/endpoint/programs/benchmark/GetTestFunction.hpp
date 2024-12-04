/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_BENCHMARK_FUNCTIONS_
#define _PRIVMXLIB_ENDPOINT_BENCHMARK_FUNCTIONS_

#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include "privmx/endpoint/programs/benchmark/Types.hpp"

std::function<
    void(
        std::shared_ptr<privmx::endpoint::core::Connection>, 
        std::shared_ptr<privmx::endpoint::thread::ThreadApi>, 
        std::shared_ptr<privmx::endpoint::store::StoreApi>, 
        std::shared_ptr<privmx::endpoint::inbox::InboxApi>, 
        const std::vector<std::string>&
    )
> GetTestFunctionThread(uint64_t fun_number);

std::function<
    void(
        std::shared_ptr<privmx::endpoint::core::Connection>, 
        std::shared_ptr<privmx::endpoint::thread::ThreadApi>, 
        std::shared_ptr<privmx::endpoint::store::StoreApi>, 
        std::shared_ptr<privmx::endpoint::inbox::InboxApi>, 
        const std::vector<std::string>&
    )
> GetTestFunctionStore(uint64_t fun_number);


std::function<
    void(
        std::shared_ptr<privmx::endpoint::core::Connection>, 
        std::shared_ptr<privmx::endpoint::thread::ThreadApi>, 
        std::shared_ptr<privmx::endpoint::store::StoreApi>, 
        std::shared_ptr<privmx::endpoint::inbox::InboxApi>, 
        const std::vector<std::string>&
    )
> GetTestFunctionInbox(uint64_t fun_number);

std::function<
    void(
        std::shared_ptr<privmx::endpoint::core::Connection>, 
        std::shared_ptr<privmx::endpoint::thread::ThreadApi>, 
        std::shared_ptr<privmx::endpoint::store::StoreApi>, 
        std::shared_ptr<privmx::endpoint::inbox::InboxApi>, 
        const std::vector<std::string>&
    )
> GetTestFunctionCrypto(uint64_t fun_number);

std::function<
    void(
        std::shared_ptr<privmx::endpoint::core::Connection>, 
        std::shared_ptr<privmx::endpoint::thread::ThreadApi>, 
        std::shared_ptr<privmx::endpoint::store::StoreApi>, 
        std::shared_ptr<privmx::endpoint::inbox::InboxApi>, 
        const std::vector<std::string>&
    )
> GetTestFunction(Module module, uint64_t fun_number);

#endif // _PRIVMXLIB_ENDPOINT_BENCHMARK_FUNCTIONS_