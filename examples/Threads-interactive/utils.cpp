#include <optional>
#include <iostream>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <fstream>
#include <vector>
#include <map>
#include <filesystem>
#include <ncurses.h>
#include "utils.hpp"

std::map<std::string, std::string> utils::loadSettings(const std::string& filePath) {
	const std::filesystem::path f{filePath};
	if (! std::filesystem::exists(f)) {
		std::cerr << "Error: no configuration file at location: " << filePath << ". Exiting.." << std::endl;
		exit(-1);
	}
	std::map<std::string, std::string> map;
	std::ifstream fin(filePath);

	std::string line;
	std::string delimiter = "=";

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

void utils::printOption(const std::string & selector, const std::string & option) {
	printw("%s\t%s\n",selector.c_str(), option.c_str());
}

void utils::printOption(const std::string & selector, const std::string & option, const std::string & option2) {
	// std::cout << selector << " " << option << " " << option2 << std::endl;
    printw("%s\t%s\t%s\n",selector.c_str(), option.c_str(), option2.c_str());
}

std::string utils::renderMsg(const privmx::endpoint::thread::Message& message) {
	return "<" + message.info.author + ">: " + "\t" + message.data.stdString() + "\n";
}

void utils::printMsg(const privmx::endpoint::thread::Message& message) {
    printw("%s", renderMsg(message).c_str());
}

void utils::printMsg(const std::string& userId, const std::string& msg) {
	// std::cout << "<" << userId << ">: "<< "\t" << msg << std::endl;
    printw("<%s>: %s\n",userId.c_str(), msg.c_str());
}

void utils::printMenu() {
	printw("\n");
	printOption(":H", "List of options");
	printOption(":C", "clear screen");
	printOption(":T", "List threads");
	printOption(":USE <thread item id>", "use selected thread");
	printOption("(CTRL+C)", "Exit");
	printw("\n");
	printOption("(write any text not starting with ':' and press ENTER to send a message - if on a thread)","");
}
void utils::clearScreen() {
	// std::cout << "\033[2J\033[1;1H";
    clear();
}

void utils::printPrompt(const std::string& threadId, const std::string& input) {
	int y, x;
	getyx(stdscr, y, x);
	move(y, 0);
	clrtoeol();
	printw("%s >> %s", threadId.c_str(), input.c_str());
}

void utils::setupNCurses() {
	initscr();
	noecho();
	cbreak();
	scrollok(stdscr, TRUE);
	timeout(-1);
	keypad(stdscr, TRUE);
}

void utils::printQueueStringItem(const ConsoleItem& item) {
	int y, x;
	getyx(stdscr, y, x);
	move(y, 0);
	clrtoeol();
	printw("%s", item.stringValue.c_str());
	refresh();
}