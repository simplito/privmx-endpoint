#ifndef _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_

#include <optional>
#include <string>

#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace core {

struct EncKey {
    std::string id;
    std::string key;
};


}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_
