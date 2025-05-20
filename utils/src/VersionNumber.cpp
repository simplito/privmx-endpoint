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
#include "privmx/utils/Utils.hpp"
#include <regex>

using namespace privmx;
using namespace privmx::utils;

VersionNumber::VersionNumber(): _versionStr("unknown"), _major(0), _minor(0) {}
VersionNumber::VersionNumber(const std::string& versionStr): _versionStr(versionStr) {
    std::regex versionRegex("^(\\d+\\.)(\\d+)(\\.)?(\\*|\\d+[0-9a-zA-Z\\-\\_]*)?$");
    if(!std::regex_match(versionStr, versionRegex)) {
        throw InvalidVersionFormatException(versionStr);
    }
    // To Make processing easier in VersionDigit prepend a '.'
    try {
        auto tmp = privmx::utils::Utils::split(versionStr, ".");
        _major = std::stoul(tmp[0]);
        _minor = std::stoul(tmp[1]);
        if(tmp.size() == 3 && tmp[2] != "*") {
            size_t pos;
            _build = std::stoul(tmp[2], &pos);
            if(pos != tmp[2].length()) {
                _comment = tmp[2].substr(pos);
            }
        }
    } catch (...) {
        throw InvalidVersionFormatException(versionStr);
    }
}

bool VersionNumber::operator<(const VersionNumber& rhs) const {
    if(_major < rhs._major) {
        return true;
    } else if(_major == rhs._major) {
        if(_minor < rhs._minor) {
            return true;
        } else if(_minor == rhs._minor) {
            if(!_build.has_value() || (rhs._build.has_value() && _build.value() < rhs._build.value())) {
                return true;
            } else if(_build.has_value() && rhs._build.has_value() && _build.value() == rhs._build.value()) {
                if(_comment.has_value() && rhs._comment.has_value()) {
                    return std::lexicographical_compare(_comment.value().begin(), _comment.value().end(), rhs._comment.value().begin(), rhs._comment.value().end());
                } else if(_comment.has_value()) {
                    return true;
                }
            }
        }
    }
    return false;
} 

bool VersionNumber::operator>(const VersionNumber& rhs) const {
    return rhs.operator<(*this);
}

bool VersionNumber::operator==(VersionNumber const& rhs) const {
    if (_major == rhs._major && _minor == rhs._minor) {
        if (_build.has_value() && rhs._build.has_value() && _build == rhs._build) {
            if (_comment.has_value() && rhs._comment.has_value() && _comment == rhs._comment) {
                return true;
            } else if (!_comment.has_value() && !rhs._comment.has_value()) {
                return true;
            }
        } else if (!_build.has_value() && !rhs._build.has_value()) {
            return true;
        }
    }
    return false;
}

