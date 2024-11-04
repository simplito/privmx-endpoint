/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_INIFILEREADER_HPP_
#define _PRIVMXLIB_UTILS_INIFILEREADER_HPP_

#include <sstream>
#include <vector>
#include <algorithm> 
#include <cctype>
#include <locale>

namespace privmx {
namespace utils {

struct Pair {
    std::string name;
    std::string value;
};

class IniFileReader {
public:
    IniFileReader(const std::string& iniFile);
    std::string getString(const std::string& name);
private:
    std::string readFile(const std::string filePath);
    std::vector<std::string> splitStringByCharacter(const std::string& str, char character);
    void ltrim(std::string &s);
    void rtrim(std::string &s);
    std::string trim(std::string &s);
    


    std::string _iniFile;
    std::vector<Pair> _params;
};
} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_INIFILEREADER_HPP_