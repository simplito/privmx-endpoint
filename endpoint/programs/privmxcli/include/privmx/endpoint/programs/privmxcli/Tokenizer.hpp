/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_TOKENIZER_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_TOKENIZER_HPP_


#include <vector>
#include <string>


#include "privmx/endpoint/programs/privmxcli/GlobalVariables.hpp"

namespace privmx {
namespace endpoint {
namespace privmxcli {

class Tokenizer {
public:
    static TokensInfo tokenize(const std::string &line);
};
} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_TOKENIZER_HPP_