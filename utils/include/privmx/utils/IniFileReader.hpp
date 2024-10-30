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