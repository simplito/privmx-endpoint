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

CancellationToken::CancellationToken() : _canceled(false) {}

CancellationToken::CancellationToken(CancellationToken::Ptr token) : _canceled(token->isCanceled()) {
    _parent = Task(token, [&]{ cancel(); });
}

void CancellationToken::cancel() {
    UniqueLock lock(_mutex);
    _canceled.store(true);
    _cv.notify_all();
    auto copy = _tasks;
    lock.unlock();
    for (auto& task : copy) {
        task.second();
    }
}

int CancellationToken::registerTask(const function<void(void)>& func) {
    UniqueLock lock(_mutex);
    validate();
    int id = ++_id;
    _tasks.emplace(id, func);
    return id;
}

void CancellationToken::unregisterTask(int id) {
    UniqueLock lock(_mutex);
    auto it = _tasks.find(id);
    if (it != _tasks.end()) {
        _tasks.erase(it);
    }
}
