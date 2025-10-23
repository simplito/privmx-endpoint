/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/


#include "privmx/endpoint/core/SingletonsHolder.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
using namespace privmx::endpoint::core;

SingletonsHolder* SingletonsHolder::impl = new SingletonsHolder();
SingletonsHolder* SingletonsHolder::getInstance() {
    if(!impl) {
        throw InvalidSingletonsHolderStateException();
    }
    return impl;
}



SingletonsHolder::SingletonsHolder() {
    #ifdef PRIVMX_ENABLE_LOGGER
        _logger = privmx::logger::Logger::getInstance();
    #endif
    _executor = privmx::utils::Executor::getInstance();
    _eventQueueImpl = privmx::endpoint::core::EventQueueImpl::getInstance();
    LOG_TRACE("SingletonsHolder created")
}

SingletonsHolder::~SingletonsHolder() {
    LOG_TRACE("SingletonsHolder deconstructing")
    _eventQueueImpl.reset();
    privmx::endpoint::core::EventQueueImpl::freeInstance();
    _executor.reset();
    privmx::utils::Executor::freeInstance();
    #ifdef PRIVMX_ENABLE_LOGGER
        _logger.reset();
        privmx::logger::Logger::freeInstance();
    #endif

}

static SingletonsHolder_destroyer singletonsHolder_destroyer;