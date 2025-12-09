#include <optional>
#include <iostream>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/core/Buffer.hpp>


using namespace privmx::endpoint;
int main() {
	// the values below should be replaced by the ones corresponding to your Brigde Server instance.
        auto platformUrl {"<YOUR_BRIDGE_URL_HERE>"};
        auto solutionId {"<YOUR_SOLUTION_ID_HERE>"};
        auto contextId {"<YOUR_CONTEXT_ID_HERE>"};

        auto userId {"<YOUR_USER_ID_HERE>"};
        auto userPubKey {"<YOUR_USER_PUB_KEY_HERE>"};
        auto userPrivKey {"<YOUR_USER_PRIV_KEY_HERE>"};
	
	// setup some defaults
	core::PagingQuery defaultListQuery = {.skip = 0, .limit = 100, .sortOrder = "desc"};
	std::vector<core::UserWithPubKey> threadUsers;
	threadUsers.push_back({.userId = userId, .pubKey = userPubKey});
	
	// initialize Endpoint connection and Threads API
	auto connection {core::Connection::connect(userPrivKey, solutionId, platformUrl)};
	auto threadApi {thread::ThreadApi::create(connection)};
	auto threadId {threadApi.createThread(contextId, threadUsers, threadUsers, core::Buffer::from("some thread's public meta-data"), core::Buffer::from("some thread's private meta-data"))};

	// send messages to thread and read them back
	threadApi.sendMessage(threadId, core::Buffer::from("some public meta-data"), core::Buffer::from("some private meta-data"), core::Buffer::from("message"));

	// get thread's messages
	auto messages = threadApi.listMessages(threadId, defaultListQuery);
	for (auto msg: messages.readItems) {
		std::cout << "message: " << msg.data.stdString()
			<< " / public meta: " << msg.publicMeta.stdString() 
			<< " / private meta: " << msg.privateMeta.stdString() 
			<< std::endl;
		}
	return 0;
}
