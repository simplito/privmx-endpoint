/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/utils/CancellationToken.hpp>

using namespace privmx::utils;
using namespace std;

CancellationToken::Task::Task() {}

CancellationToken::Task::Task(CancellationToken::Ptr token, const function<void(void)>& func) : _token(token) {
    _id = _token->registerTask(func);
}

CancellationToken::Task::~Task() {
    if (_id != -1)
        _token->unregisterTask(_id);
}

CancellationToken::Ptr CancellationToken::create() {
    return new CancellationToken();
}

CancellationToken::Ptr CancellationToken::create(CancellationToken::Ptr token) {
    return new CancellationToken(token);
}

CancellationToken::CancellationToken() : _cancelled(false) {
    std::cerr << "CancellationToken constructor: " << this << std::endl; // Debug by Patryk
}

CancellationToken::CancellationToken(CancellationToken::Ptr token) : _cancelled(token->isCancelled()) {
    _parent = Task(token, [&]{ cancel(); });
    std::cerr << "CancellationToken constructor: " << this << std::endl; // Debug by Patryk
}

CancellationToken::~CancellationToken() {
    std::cerr << "CancellationToken deconstructor: " << this << std::endl; // Debug by Patryk
}

void CancellationToken::cancel() {
    std::cerr << "CancellationToken cancel: " << this << std::endl; // Debug by Patryk
    UniqueLock lock(_mutex);
    _cancelled.store(true);
    _cv.notify_all();
    auto copy = _tasks;
    lock.unlock();
    for (auto& task : copy) {
        task.second();
    }
}

int CancellationToken::registerTask(const function<void(void)>& func) {
    std::cerr << "CancellationToken registerTask: " << this << std::endl; // Debug by Patryk
    UniqueLock lock(_mutex);
    validate();
    int id = ++_id;
    _tasks.emplace(id, func);
    return id;
}

void CancellationToken::unregisterTask(int id) {
    std::cerr << "CancellationToken unregisterTask: " << this << std::endl; // Debug by Patryk
    UniqueLock lock(_mutex);
    auto it = _tasks.find(id);
    if (it != _tasks.end()) {
        _tasks.erase(it);
    }
}
