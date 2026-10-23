/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

// Small helpers several unit tests share.

#pragma once

#include <chrono>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

#include <Poco/JSON/Object.h>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/EventQueueImpl.hpp>
#include <privmx/utils/Utils.hpp>

// A Connection over an impl the test built itself (e.g. `ConnectionImpl::connectOver` a fake gateway).
struct ConnectionOf : privmx::endpoint::core::Connection {
    explicit ConnectionOf(const std::shared_ptr<privmx::endpoint::core::ConnectionImpl>& impl) { _ptr = impl; }
};

// A value as it arrives in a notification: serialized and parsed back.
inline Poco::JSON::Object::Ptr overTheWire(const Poco::Dynamic::Var& value) {
    return privmx::utils::Utils::parseJsonObject(privmx::utils::Utils::stringifyVar(value));
}

// The next event of `type` from the shared queue; the others are dropped.
inline privmx::endpoint::core::EventHolder nextEvent(const std::string& type) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        if (const auto event = privmx::endpoint::core::EventQueueImpl::getInstance()->getEvent(); event.has_value()) {
            if (event->type() == type) {
                return event.value();
            }
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    throw std::runtime_error("no " + type + " event");
}

// A policy object as the bridge stores and serves it.
inline Poco::Dynamic::Var policyOf(const std::map<std::string, std::string>& rules) {
    Poco::JSON::Object::Ptr policy = new Poco::JSON::Object();
    for (const auto& [field, rule] : rules) {
        policy->set(field, rule);
    }
    return policy;
}
