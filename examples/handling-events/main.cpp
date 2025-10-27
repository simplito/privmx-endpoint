#include <optional>
#include <iostream>
#include <thread>
#include <vector>
#include <string_view>
#include <algorithm>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/thread/Events.hpp>

using namespace privmx::endpoint;

int main(int argc, char* argv[]) {
	// the values below should be replaced by the ones corresponding to your Brigde Server instance.
	auto BRIDGE_URL {"<YOUR_BRIDGE_URL_HERE>"};
	auto SOLUTION_ID {"<YOUR_SOLUTION_ID_HERE>"};
	auto CONTEXT_ID {"<YOUR_CONTEXT_ID_HERE>"};
	
	auto USER1_ID {"<YOUR_USER_ID_HERE>"};
	auto USER1_PUBLIC_KEY {"<YOUR_USER_PUB_KEY_HERE>"};
	auto USER1_PRIVATE_KEY {"<YOUR_USER_PRIV_KEY_HERE>"};

	core::EventQueue eventQueue {core::EventQueue::getInstance()};

	// Start the EventQueue reading loop
	std::thread t([&](){
		while(true) {
			core::EventHolder event = eventQueue.waitEvent();
			if (thread::Events::isThreadNewMessageEvent(event)) {
				auto msgEvent = thread::Events::extractThreadNewMessageEvent(event);
				auto message = msgEvent.data;
				std::cout << "Message: " << message.data.stdString() << std::endl;
				std::cout << "Author: " << message.info.author << std::endl;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
	});

	// initialize Endpoint connection and Threads API
	auto connection {core::Connection::connect(USER1_PRIVATE_KEY, SOLUTION_ID, BRIDGE_URL)};
	auto threadApi {thread::ThreadApi::create(connection)};
	core::PagingQuery defaultListQuery = {.skip = 0, .limit = 100, .sortOrder = "desc"};

	// Get a Thread to work with
	auto currentThread {threadApi.listThreads(CONTEXT_ID, defaultListQuery).readItems[0]};

	// Subscribe for the Thread's events
	threadApi.subscribeForMessageEvents(currentThread.threadId);

	// Send a sample message
	threadApi.sendMessage(currentThread.threadId, core::Buffer::from(""), core::Buffer::from(""), core::Buffer::from("some message"));

	t.join();
	
	return 0;
}
