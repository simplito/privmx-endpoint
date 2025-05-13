#include <optional>
#include <iostream>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/core/Buffer.hpp>


using namespace privmx::endpoint;
int main() {
	// the values below should be replaced by the ones corresponding to your Brigde Server instance.
	auto BRIDGE_URL {"http://localhost:9111"};
	auto SOLUTION_ID {"924d3b49-5206-43ab-a1cc-7539e0b9977d"};
	auto CONTEXT_ID {"5319f785-9a45-4614-a638-e47b5152b610"};
	
	auto USER1_ID {"user1"};
	auto USER1_PUBLIC_KEY {"51WPnnGwztNPWUDEbhncYDxZCZWAFS4M9Yqv94N2335nL92fEn"};
	auto USER1_PRIVATE_KEY {"L3ycXibEzJm9t9swoJ4KtSmJsenHmmgRnYY79Q2TqfJMwTGaWfA7"};

	// initialize Endpoint connection and Threads API
	auto connection {core::Connection::connect(USER1_PRIVATE_KEY, SOLUTION_ID, BRIDGE_URL)};
	auto threadApi {thread::ThreadApi::create(connection)};

	// Define the custom field for the Threads
	std::string threadCustomField = R"(
	    {
			"threadType": "special"
    	}
	)";

	
	std::vector<core::UserWithPubKey> threadUsers {
		{.userId = USER1_ID, .pubKey = USER1_PUBLIC_KEY}
	};

	// Creating some ordinary Threads
	for (int i = 0; i < 3; ++i) {
		threadApi.createThread(
			CONTEXT_ID, 
			threadUsers, threadUsers, 
			core::Buffer::from(""),
			core::Buffer::from("Ordinary thread")
		);
	}

	// Creating some Threads with the custom field
	for (int i = 0; i < 3; ++i) {
		threadApi.createThread(
			CONTEXT_ID, 
			threadUsers, threadUsers, 
			core::Buffer::from(threadCustomField),
			core::Buffer::from("Thread with the custom field")
		);
	}

	// Quering over Threads
	core::PagingQuery defaultListQuery = {.skip = 0, .limit = 10, .sortOrder = "desc"};
	auto threadsList1 {threadApi.listThreads(CONTEXT_ID, defaultListQuery)};

	core::PagingQuery customQuery = {.skip = 0, .limit = 10, .sortOrder = "desc", .queryAsJson = threadCustomField};
	auto threadsList2 {threadApi.listThreads(CONTEXT_ID, customQuery)};

	std::cout << "The list of all Threads:" << std::endl;
	for (auto t: threadsList1.readItems) {
		std::cout << "ThreadId: " << t.threadId << " / privateMeta: " << t.privateMeta.stdString() << std::endl;
	}

	std::cout << "The list of Threads with the custom field:" << std::endl;
	for (auto t: threadsList2.readItems) {
		std::cout << "ThreadId: " << t.threadId << " / privateMeta: " << t.privateMeta.stdString() << std::endl;
	}

	return 0;
}
