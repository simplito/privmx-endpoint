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
	auto BRIDGE_URL {"http://localhost:9111"};
	auto SOLUTION_ID {"924d3b49-5206-43ab-a1cc-7539e0b9977d"};
	auto CONTEXT_ID {"5319f785-9a45-4614-a638-e47b5152b610"};
	
	auto USER1_ID {"user1"};
	auto USER1_PUBLIC_KEY {"51WPnnGwztNPWUDEbhncYDxZCZWAFS4M9Yqv94N2335nL92fEn"};
	auto USER1_PRIVATE_KEY {"L3ycXibEzJm9t9swoJ4KtSmJsenHmmgRnYY79Q2TqfJMwTGaWfA7"};

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
