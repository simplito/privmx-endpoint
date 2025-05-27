/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_VERSIONNUMBER_HPP_
#define _PRIVMXLIB_UTILS_VERSIONNUMBER_HPP_

#include <iostream>
#include <sstream>
#include <vector>
#include <iterator>
#include <optional>
namespace privmx {
namespace utils {

class VersionNumber {
public:
    VersionNumber();
    VersionNumber(const std::string& versionStr);
    bool operator<(VersionNumber const& rhs) const;
    bool operator>(VersionNumber const& rhs) const;
    bool operator==(VersionNumber const& rhs) const;
    operator std::string() const {return _versionStr;}
private:
    std::string _versionStr;
    size_t _major;
    size_t _minor;
    std::optional<size_t> _build;
    std::optional<std::string> _comment;
};

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_VERSIONNUMBER_HPP_