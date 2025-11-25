#ifndef _PRIVMXLIB_ENDPOINT_CORE_EXTENDEDPOINTER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_EXTENDEDPOINTER_HPP_

#include <memory>
#include <string>
#include <optional>
#include <iostream>

#include "privmx/endpoint/core/CoreException.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template <typename T>
class ExtendedPointer {
public:

    ExtendedPointer();
    ExtendedPointer(const ExtendedPointer& obj);
    ExtendedPointer& operator=(const ExtendedPointer& obj);
    ExtendedPointer(ExtendedPointer&& obj);
    ~ExtendedPointer();

    ExtendedPointer(std::shared_ptr<T> ptr);
    std::shared_ptr<T> getImpl() const;
protected:
    void attachToPtrIfPossible();
    void detachFromPtrIfPossible();
    std::weak_ptr<T> _ptr;
};

template <typename T>
ExtendedPointer<T>::ExtendedPointer() {};

template <typename T>
ExtendedPointer<T>::ExtendedPointer(const ExtendedPointer& obj) : _ptr(obj._ptr) {
    attachToPtrIfPossible();
}
template <typename T>
ExtendedPointer<T>& ExtendedPointer<T>::operator=(const ExtendedPointer<T>& obj) {
    this->_ptr = obj._ptr;
    this->attachToPtrIfPossible();
    return *this;
}
template <typename T>
ExtendedPointer<T>::ExtendedPointer(ExtendedPointer&& obj) : _ptr(obj._ptr) {
    attachToPtrIfPossible();
}
template <typename T>
ExtendedPointer<T>::~ExtendedPointer() {
    detachFromPtrIfPossible();
}

template <typename T>
ExtendedPointer<T>::ExtendedPointer(std::shared_ptr<T> ptr) : _ptr(ptr) {}

template <typename T>
std::shared_ptr<T> ExtendedPointer<T>::getImpl() const {
    auto ptr = _ptr.lock();
    if(!ptr) throw NotConnectedException();
    return ptr; 
}

template <typename T>
void ExtendedPointer<T>::attachToPtrIfPossible() {
    if(!_ptr.expired()) {
        auto ptr = _ptr.lock();
        if(ptr) {
            ptr->attach();
        }
    }
}

template <typename T>
void ExtendedPointer<T>::detachFromPtrIfPossible() {
    if(!_ptr.expired()) {
        auto ptr = _ptr.lock();
        if(ptr) {
            ptr->detach();
        }
    }
}

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_EXTENDEDPOINTER_HPP_
