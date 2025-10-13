/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_SINGLETONSHOLDER_HPP
#define _PRIVMXLIB_ENDPOINT_CORE_SINGLETONSHOLDER_HPP

#include <privmx/utils/Logger.hpp>
#include <privmx/utils/Executor.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>

namespace privmx {
namespace endpoint {
namespace core {

class SingletonsHolder
{
public:
    static SingletonsHolder* getInstance();
    SingletonsHolder(const SingletonsHolder& obj) = delete; 
    void operator=(const SingletonsHolder &) = delete;
    friend class SingletonsHolder_destroyer;
private:
    SingletonsHolder();
    ~SingletonsHolder();
    static SingletonsHolder* impl;
    std::shared_ptr<privmx::endpoint::core::EventQueueImpl> _eventQueueImpl;
    std::shared_ptr<privmx::utils::Executor> _executor;
    #ifdef PRIVMX_ENABLE_LOGGER
        std::shared_ptr<privmx::logger::Logger> _logger;
    #endif
};

class SingletonsHolder_destroyer {
public:
    ~SingletonsHolder_destroyer() { delete SingletonsHolder::impl; }
};



} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_SINGLETONSHOLDER_HPP