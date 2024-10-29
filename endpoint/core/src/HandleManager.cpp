#include "privmx/endpoint/core/HandleManager.hpp"
#include "privmx/endpoint/core/CoreException.hpp"

using namespace privmx::endpoint::core;

int64_t HandleManager::createHandle(std::string label) {
    int64_t id = ++_id;
    if(_map.has(id)) return createHandle(label);
    _map.set(id, label);
    return id;
}

std::string HandleManager::getHandleLabel(int64_t id) {
    auto result = _map.get(id);
    if(!result.has_value()) {
        throw NoHandleFoundException();
    }
    return result.value();
}

void HandleManager::removeHandle(int64_t id) {
    _map.erase(id);
}