/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_TEST_MEMORYPINSTORE_HPP_
#define _PRIVMXLIB_TEST_MEMORYPINSTORE_HPP_

#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>

#include <privmx/endpoint/core/PinStoreInterface.hpp>

// The application's store as the contract asks for it: compare-and-swap per key under one lock. Counts what it is
// asked and can be told to refuse saves, so a test sees exactly what the library wrote and when.
class MemoryPinStore : public privmx::endpoint::core::PinStoreInterface {
public:
    privmx::endpoint::core::Buffer load(const std::string& key) override {
        std::string blob;
        {
            std::lock_guard<std::mutex> lock(_mutex);
            ++loads;
            const auto it = _slots.find(key);
            blob = it == _slots.end() ? std::string() : it->second;
        }
        afterLoad(key); // what was read is already returned: a test interleaves another saver here
        return privmx::endpoint::core::Buffer::from(blob);
    }

    bool save(
        const std::string& key,
        const privmx::endpoint::core::Buffer& blob,
        const privmx::endpoint::core::Buffer& expected
    ) override {
        std::lock_guard<std::mutex> lock(_mutex);
        if (failSaves) {
            throw std::runtime_error("the store is full");
        }
        const auto it = _slots.find(key);
        const std::string current = it == _slots.end() ? std::string() : it->second;
        if (current != expected.stdString()) {
            ++casMisses;
            return false;
        }
        _slots[key] = blob.stdString();
        ++saves[key];
        return true;
    }

    std::string get(const std::string& key) {
        std::lock_guard<std::mutex> lock(_mutex);
        const auto it = _slots.find(key);
        return it == _slots.end() ? std::string() : it->second;
    }

    void put(const std::string& key, const std::string& blob) {
        std::lock_guard<std::mutex> lock(_mutex);
        _slots[key] = blob;
    }

    // The slot whose key starts with `prefix` (the tests know the kind, not the Bridge scope).
    std::string keyOf(const std::string& prefix) {
        std::lock_guard<std::mutex> lock(_mutex);
        for (const auto& [key, blob] : _slots) {
            if (key.rfind(prefix, 0) == 0) {
                return key;
            }
        }
        return {};
    }

    int savesOf(const std::string& prefix) {
        std::lock_guard<std::mutex> lock(_mutex);
        int total = 0;
        for (const auto& [key, count] : saves) {
            if (key.rfind(prefix, 0) == 0) {
                total += count;
            }
        }
        return total;
    }

    std::function<void(const std::string&)> afterLoad = [](const std::string&) {};
    std::atomic<bool> failSaves{false};
    int loads = 0;
    int casMisses = 0;
    std::map<std::string, int> saves;

private:
    std::mutex _mutex;
    std::map<std::string, std::string> _slots;
};

#endif // _PRIVMXLIB_TEST_MEMORYPINSTORE_HPP_
