#include <optional>
#include <iostream>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/core/Buffer.hpp>


using namespace privmx::endpoint;
int main() {
	// the values below should be replaced by the ones corresponding to your Brigde Server instance.
        auto BRIDGE_URL {"<YOUR_BRIDGE_URL_HERE>"};
        auto SOLUTION_ID {"<YOUR_SOLUTION_ID_HERE>"};
        auto CONTEXT_ID {"<YOUR_CONTEXT_ID_HERE>"};

        auto USER1_ID {"<YOUR_USER_ID_HERE>"};
        auto USER1_PUBLIC_KEY {"<YOUR_USER_PUB_KEY_HERE>"};
        auto USER1_PRIVATE_KEY {"<YOUR_USER_PRIV_KEY_HERE>"};

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
