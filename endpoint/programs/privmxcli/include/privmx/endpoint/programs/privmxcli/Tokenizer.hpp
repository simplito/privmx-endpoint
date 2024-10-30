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