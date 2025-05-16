/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/utils/VersionNumber.hpp"
#include "privmx/utils/PrivmxExtExceptions.hpp"
#include <regex>

using namespace privmx;
using namespace privmx::utils;

VersionNumber::VersionNumber(): _versionStr("unknown"), _versionInfo(std::vector<size_t>({})) {}
VersionNumber::VersionNumber(const std::string& versionStr): _versionStr(versionStr) {
    std::regex versionRegex("^(?:(\\d+)\\.)+(\\d+)$");
    if(!std::regex_match(versionStr, versionRegex)) {
        throw InvalidVersionFormatException(versionStr);
    }
    // To Make processing easier in VersionDigit prepend a '.'
    std::stringstream versionStream(std::string(".") + versionStr);

    // Copy all parts of the version number into the version Info vector.
    std::copy(
        std::istream_iterator<VersionDigit>(versionStream),
        std::istream_iterator<VersionDigit>(),
        std::back_inserter(_versionInfo)
    );
}

bool VersionNumber::operator<(VersionNumber const& rhs) const {
    return std::lexicographical_compare(_versionInfo.begin(), _versionInfo.end(), rhs._versionInfo.begin(), rhs._versionInfo.end());
} 
bool VersionNumber::operator>(VersionNumber const& rhs) const {
    return std::lexicographical_compare(rhs._versionInfo.begin(), rhs._versionInfo.end(), _versionInfo.begin(), _versionInfo.end());
}
bool VersionNumber::operator==(VersionNumber const& rhs) const {
    if(rhs._versionInfo.size() != _versionInfo.size()) {
        return false;
    }
    for(size_t i = 0; i < _versionInfo.size(); i++) {
        if(rhs._versionInfo[i] != _versionInfo[i]) {
            return false;
        }
    }
    return true;
}

