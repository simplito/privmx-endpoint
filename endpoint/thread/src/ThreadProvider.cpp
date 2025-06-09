/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/ThreadProvider.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

ThreadProvider::ThreadProvider(std::function<server::ThreadInfo(std::string)> getThread, std::function<uint32_t(server::ThreadInfo)> validateThread) 
    : core::ContainerProvider<std::string, server::ThreadInfo>(getThread, validateThread) {}
    
bool ThreadProvider::isNewerOrSameAsInStorage(const server::ThreadInfo& container) {
    auto cached = _storage.get(container.id());
    if (!cached.has_value()) {
        return true;
    }
    auto cached_container = cached.value().container;
    if (container.version() > cached_container.version() ||
        (container.lastModificationDate() >= cached_container.lastModificationDate() && container.version() == cached_container.version())
    ) {
        return true;
    }
    return false;
}

void ThreadProvider::updateStats(const server::ThreadStatsEventData& stats) {
    auto threadInfo = this->get(stats.threadId()).container;
    threadInfo.messages(stats.messages());
    threadInfo.lastMsgDate(stats.lastMsgDate());
    updateByValue(threadInfo);
}