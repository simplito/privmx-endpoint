#include <privmx/rpc/EventDispatcher.hpp>

using namespace privmx::rpc;

int EventDispatcher::addEventListener(const std::string& type, std::function<void(Poco::JSON::Object::Ptr)> event_listener) {
    int id = _current_id++;
    utils::Lock lock(_mutex);
    _map[type][id] = event_listener;
    return id;
}

void EventDispatcher::removeEventListener(const std::string& type, int listener_id) {
    utils::Lock lock(_mutex);
    auto it = _map.find(type);
    if (it == _map.end()) return;
    (*it).second.erase(listener_id);
}

void EventDispatcher::dispatchEvent(Poco::JSON::Object::Ptr event) {
    auto type = event->getValue<std::string>("type");
    std::unordered_map<int, std::function<void(Poco::JSON::Object::Ptr)>> tmp;
    {
        utils::Lock lock(_mutex);
        auto it = _map.find(type);
        if (it == _map.end()) return;
        tmp = (*it).second;
    }
    for (auto& x : tmp) {
        if (x.second) {
            try {
                x.second(event);
            } catch (...) {}
        }
    }
}

void EventDispatcher::clear() {
    utils::Lock lock(_mutex);
    _map.clear();
}
