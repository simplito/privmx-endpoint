/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_STRING_ARRAY_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_STRING_ARRAY_HPP_

#include <vector>
#include <string>

namespace privmx {
namespace endpoint {
namespace privmxcli {

class StringArray
{
public:
    StringArray(const std::vector<std::string> &list);
    StringArray(const StringArray& obj);
    StringArray(StringArray&& obj);
    const char** data() const;
    std::string str() const;

private:
    void copyStringsPtrs();

    std::vector<std::string> array;
    char *val[100];
};

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_STRING_ARRAY_HPP_