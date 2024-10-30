#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <iostream>

#include <Poco/StreamCopier.h>

#include <privmx/utils/IniFileReader.hpp>

using namespace privmx;
using namespace privmx::utils;

IniFileReader::IniFileReader(const std::string& iniFile): _iniFile{iniFile} {
    _params = {};
    auto contents {readFile(_iniFile)};
    auto lines {splitStringByCharacter(contents, '\n')};
    
    for(auto &line: lines) {
        std::size_t separatorPos = line.find("=");
        if (separatorPos == std::string::npos) {
            continue;
        }
        auto param {splitStringByCharacter(line, '=')};
        _params.push_back({.name = param.at(0), .value = param.at(1)});
    }
}

std::string IniFileReader::readFile(const std::string filePath) {
    std::ifstream input(filePath, std::ios::binary);
    std::stringstream strStream;
    strStream << input.rdbuf();
    input.close();
    return strStream.str();
}

std::vector<std::string> IniFileReader::splitStringByCharacter(const std::string& str, char character) {
    auto result = std::vector<std::string>{};
    auto ss = std::stringstream{str};
    std::string _namespace {""};
    
    for (std::string line; std::getline(ss, line, character);) {
        auto trimmed {trim(line)};
        if (trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }
        if (trimmed[0] == '[' && trimmed[trimmed.size() -1 ] == ']') {
            _namespace = trimmed.substr(1, trimmed.size() - 2) + ".";
        }
        result.push_back(_namespace + trim(line));
    }

    return result;
}

std::string IniFileReader::getString(const std::string& name) {
    for (auto &param : _params) {
        if (param.name == name) {
            return param.value;
        }
    }
    return "";
}

void IniFileReader::ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

void IniFileReader::rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

std::string IniFileReader::trim(std::string &s) {
    rtrim(s);
    ltrim(s);
    return s;
}
