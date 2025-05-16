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

namespace privmx {
namespace utils {

class VersionNumber {
private:
    std::string _versionStr;
    std::vector<size_t> _versionInfo;
    // An internal utility structure just used to make the std::copy in the constructor easy to write.
    struct VersionDigit{
        size_t value;
        operator size_t() const {return value;}
    };
    friend std::istream& operator>>(std::istream& str, VersionNumber::VersionDigit& digit) {
        str.get();
        str >> digit.value;
        return str;
    }
public:
    VersionNumber();
    VersionNumber(const std::string& versionStr);
    bool operator<(VersionNumber const& rhs) const;
    bool operator>(VersionNumber const& rhs) const;
    bool operator==(VersionNumber const& rhs) const;
    operator std::string() const {return _versionStr;}
};

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_VERSIONNUMBER_HPP_