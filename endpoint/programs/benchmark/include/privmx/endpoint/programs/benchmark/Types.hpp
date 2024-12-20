/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_BENCHMARK_TYPES_
#define _PRIVMXLIB_ENDPOINT_BENCHMARK_TYPES_

#include <unordered_map>
#include <string>

enum Mode {
    Times,
    Timeout
};

inline std::unordered_map<std::string, Mode> mode_names = {
    {"0", Mode::Times},
    {"Count", Mode::Times},
    {"count", Mode::Times},
    {"N-times", Mode::Times},
    {"n-times", Mode::Times},
    {"1", Mode::Timeout},
    {"Timeout", Mode::Timeout},
    {"timeout", Mode::Timeout}
};

enum Module {
    thread,
    store,
    inbox,
    crypto
};

inline std::unordered_map<std::string, Module> module_names = {
    {"Thread", Module::thread},
    {"thread", Module::thread},
    {"Store", Module::store},
    {"store", Module::store},
    {"Inbox", Module::inbox},
    {"inbox", Module::inbox},
    {"Crypto", Module::crypto},
    {"crypto", Module::crypto}
};

#endif // _PRIVMXLIB_ENDPOINT_BENCHMARK_TYPES_