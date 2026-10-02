#ifndef _PRIVMXLIB_ENDPOINT_CORE_BASE_API_CLASS_HPP
#define _PRIVMXLIB_ENDPOINT_CORE_BASE_API_CLASS_HPP
#include <cstddef>
#include <memory>

#include "privmx/endpoint/core/CoreException.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<typename T>
class BaseApiClass {
public:
    BaseApiClass() : _ptr(nullptr) {}
    BaseApiClass(const std::shared_ptr<T>& ptr) : _ptr(ptr) {}
    std::shared_ptr<T> getImpl() const;

protected:
    std::shared_ptr<T> _ptr;
};

template<typename T>
std::shared_ptr<T> BaseApiClass<T>::getImpl() const {
    if (!_ptr)
        throw NotInitializedException();
    return _ptr;
}

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_BASE_API_CLASS_HPP
