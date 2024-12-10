/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_BENCHMARK_DATA_
#define _PRIVMXLIB_ENDPOINT_BENCHMARK_DATA_

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


std::vector<std::string> PrepareInitDataThread(
    std::shared_ptr<privmx::endpoint::core::Connection> connection, 
    std::shared_ptr<privmx::endpoint::thread::ThreadApi> threadApi, 
    std::shared_ptr<privmx::endpoint::store::StoreApi> storeApi, 
    std::shared_ptr<privmx::endpoint::inbox::InboxApi> inboxApi,
    std::string userId,
    std::string userPubKey,
    uint64_t fun_number
);

std::vector<std::string> PrepareInitDataStore(
    std::shared_ptr<privmx::endpoint::core::Connection> connection, 
    std::shared_ptr<privmx::endpoint::thread::ThreadApi> threadApi, 
    std::shared_ptr<privmx::endpoint::store::StoreApi> storeApi, 
    std::shared_ptr<privmx::endpoint::inbox::InboxApi> inboxApi,
    std::string userId,
    std::string userPubKey,
    uint64_t fun_number
);


std::vector<std::string> PrepareInitDataInbox(
    std::shared_ptr<privmx::endpoint::core::Connection> connection, 
    std::shared_ptr<privmx::endpoint::thread::ThreadApi> threadApi, 
    std::shared_ptr<privmx::endpoint::store::StoreApi> storeApi, 
    std::shared_ptr<privmx::endpoint::inbox::InboxApi> inboxApi,
    std::string userId,
    std::string userPubKey,
    uint64_t fun_number
);

std::vector<std::string> PrepareInitDataCrypto(
    std::shared_ptr<privmx::endpoint::core::Connection> connection, 
    std::shared_ptr<privmx::endpoint::thread::ThreadApi> threadApi, 
    std::shared_ptr<privmx::endpoint::store::StoreApi> storeApi, 
    std::shared_ptr<privmx::endpoint::inbox::InboxApi> inboxApi,
    std::string userId,
    std::string userPubKey,
    uint64_t fun_number
);

std::vector<std::string> PrepareInitData(
    std::shared_ptr<privmx::endpoint::core::Connection> connection, 
    std::shared_ptr<privmx::endpoint::thread::ThreadApi> threadApi, 
    std::shared_ptr<privmx::endpoint::store::StoreApi> storeApi, 
    std::shared_ptr<privmx::endpoint::inbox::InboxApi> inboxApi,
    std::string userId,
    std::string userPubKey,
    Module module, 
    uint64_t fun_number
);

#endif // _PRIVMXLIB_ENDPOINT_BENCHMARK_DATA_