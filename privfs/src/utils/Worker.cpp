/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/utils/Worker.hpp>
#include <privmx/privfs/PrivFsException.hpp>

using namespace privmx::utils;
using namespace std;

Worker::Worker() : _running(false) {}

Worker::~Worker() {
    try {
        tryStop();
    } catch (...) {}
}

void Worker::start(const function<void(CancellationToken::Ptr)>& func, CancellationToken::Ptr token) {
    bool val = _running.exchange(true);
    if (val) {
        throw privfs::WorkerRunningException();
    }
    _token = CancellationToken::create(token);
    _thread = std::thread(func, _token);
}

void Worker::stop() {
    tryStop();
}

void Worker::tryStop() {
    if (_token)
        _token->cancel();
    try {
        if (_thread.joinable()) {
            _thread.join();
        }
    } catch (...) {}
    _running.store(false);
}
