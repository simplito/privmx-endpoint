#include <optional>
#include <iostream>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/thread/Events.hpp>
#include <fstream>
#include <vector>
#include <map>
#include <filesystem>
#include <thread>
#include <chrono>
#include <ncurses.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.hpp"

using namespace privmx::endpoint;
using namespace utils;

void processKeyPress(thread::ThreadApi& threadApi, const std::string& contextId, std::string& currentInput, std::string& currentThread, int keyCode);

void sigint_handler(int s) {
	endwin();
	std::cout << "Exiting.." << std::endl;
	exit(1);
}

int main(int argc, char *argv[]) {
	signal(SIGINT, sigint_handler);

	std::string envPath = argc > 0 ? std::string(argv[1]) : ".env";
	auto settings {loadSettings(envPath)};

	auto solutionId {getSetting(settings, "SOLUTION_ID")};
	auto contextId {getSetting(settings, "CONTEXT_ID")};
	auto userPubKey {getSetting(settings, "USER_PUB")};
	auto userPrivKey {getSetting(settings, "USER_PRIV")};
	auto userId {getSetting(settings, "USER_ID")};
	auto platformUrl {getSetting(settings, "BRIDGE_URL")};

	TSQueue<ConsoleItem> consoleQueue;
	std::string currentThread;
	std::string currentInput;

	setupNCurses();
	clearScreen();
	printMenu();
	refresh();

	// handling events
	core::EventQueue eventQueue {core::EventQueue::getInstance()};

	std::thread t([&](){
		while(true) {
			core::EventHolder event = eventQueue.waitEvent();
			if (thread::Events::isThreadNewMessageEvent(event)) {
				auto msgEvent = thread::Events::extractThreadNewMessageEvent(event);
				ConsoleItem item = {.type = 1, .stringValue = renderMsg(msgEvent.data), .keyValue = -1};
				consoleQueue.push(item);
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
    });

	std::thread userInput([&](){
		while (true) {
			auto ch = getch();
			if (ch > 0) {
				ConsoleItem item = {.type = 0, .stringValue = "", .keyValue = ch};
				consoleQueue.push(item);
			}
	        std::this_thread::sleep_for(std::chrono::milliseconds(5));
   		}
	});
	
	// // initialize Endpoint connection and Threads API
	auto connection {core::Connection::connect(userPrivKey, solutionId, platformUrl)};
	auto threadApi {thread::ThreadApi::create(connection)};
	
	while(true) {
		while(consoleQueue.size() > 0) {
			auto item {consoleQueue.pop()};
			if (item.type == 1) {
				printQueueStringItem(item);
			} 
			else
			if (item.type == 0) {
				processKeyPress(threadApi, contextId, currentInput, currentThread, item.keyValue);
			}
		}
		printPrompt(currentThread, currentInput);
		refresh();
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}

	return 0;
}

void processKeyPress(thread::ThreadApi& threadApi, const std::string& contextId, std::string& currentInput, std::string& currentThread, int keyCode) {
	if (keyCode == KEY_BACKSPACE || keyCode == KEY_BACKSPACE || keyCode == KEY_DC || keyCode == 127) {
		currentInput = currentInput.substr(0, currentInput.size() - 1);
	}
	else
	if (keyCode == 13 || keyCode == 10) {
		if (currentInput.rfind(":T", 0) == 0) {
			clear();
			core::PagingQuery query = {.skip = 0, .limit = 30, .sortOrder = "desc"};

			auto threads {threadApi.listThreads(contextId, query)};
			for (int i = 0; i < threads.readItems.size(); ++i) {
				printOption(threads.readItems[i].threadId, threads.readItems[i].publicMeta.stdString(), threads.readItems[i].privateMeta.stdString());
			}
		}
		else
		if (currentInput.rfind(":USE", 0) == 0) {
			clear();
			auto threadId {currentInput.substr(currentInput.find(" ") + 1, currentInput.length())};
			if (threadId.length() > 0) {
				if (currentThread.length() > 0) {
					threadApi.unsubscribeFromMessageEvents(currentThread);
				}
				currentThread = threadId;
				threadApi.subscribeForMessageEvents(currentThread);
				core::PagingQuery query = {.skip = 0, .limit = 10, .sortOrder = "asc"};

				auto messages {threadApi.listMessages(threadId, query)};
				for (auto msg: messages.readItems) {
					printMsg(msg);
				}
			}
		}
		else
		if (currentInput.rfind(":C", 0) == 0) {
			clearScreen();
			refresh();
		}
		else
		if (currentInput.rfind(":H", 0) == 0) {
			printMenu();
			refresh();
		}
		else {
			if (currentThread.size() == 0) {
				printw("!! you have to select a Thread first. Use option :USE <thread item id>\n");
			} else {
				threadApi.sendMessage(currentThread, core::Buffer::from(""), core::Buffer::from(""), core::Buffer::from(currentInput));
			}
		}
		currentInput = "";
	}
	else 
	// if code is printable ASCII
	if (keyCode >= 32 && keyCode <= 126) {
		currentInput += char(keyCode);
	}
}
