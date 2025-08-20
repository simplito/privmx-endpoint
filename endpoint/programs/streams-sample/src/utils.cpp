#include <optional>
#include <iostream>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <fstream>
#include <vector>
#include <map>
#include <iomanip>
#include <filesystem>
#include "utils.hpp"

std::map<std::string, std::string> utils::loadSettings(const std::string& filePath) {
	std::cerr << __LINE__ << std::endl;
	const std::filesystem::path f{filePath};
	std::cerr << __LINE__ << std::endl;
	if (! std::filesystem::exists(f)) {
		std::cerr << "Error: no configuration file at location: " << filePath << ". Exiting.." << std::endl;
		exit(-1);
	}
	std::cerr << __LINE__ << std::endl;
	std::map<std::string, std::string> map;
	std::ifstream fin(filePath);

	std::string line;
	std::string delimiter = "=";

	std::cerr << __LINE__ << std::endl;

	while(std::getline(fin, line)) {
		auto pos = line.find(delimiter);
		if (pos > 0) {
			auto key {line.substr(0, pos)};
			auto value {line.substr(pos+1, line.length())};
			std::string processedValue = value;
			if (value[0] == '\"' || value[0] == '\'') {
				processedValue = value.substr(1, value.length() - 2);
			}
			if(key.length() != 0 && processedValue.length() != 0) {
				map.insert(make_pair(key, processedValue));
			}
		}
	}
	fin.close();
	std::cerr << __LINE__ << std::endl;
	return map;
}

std::string utils::getSetting(const std::map<std::string, std::string>& values, const std::string &key) {
	std::string ret;
    try {
        ret = values.at(key);
    }
    catch (const std::out_of_range&) {
        std::cerr << "Key \"" << key.c_str() << "\" not found" << std::endl;
    }
    return ret;
}

void utils::log(const std::string& msg) {
	auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm local_tm = *std::localtime(&now_time);
    std::cout << "[" << std::put_time(&local_tm, "%H:%M:%S") << "] " << msg << '\n';
}
