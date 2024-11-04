#include <optional>
#include <iostream>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/core/Buffer.hpp>


using namespace privmx::endpoint;
int main() {
	// the values below should be replaced by the ones corresponding to your Brigde Server instance.
	auto solutionId {"6716bb7950041e112ddeaf18"};
	auto contextId {"6716bb79763760280a77b6a0"};
	auto userPubKey {"51WPnnGwztNPWUDEbhncYDxZCZWAFS4M9Yqv94N2335nL92fEn"};
	auto userPrivKey {"L3ycXibEzJm9t9swoJ4KtSmJsenHmmgRnYY79Q2TqfJMwTGaWfA7"};
	auto userId {"user1"};
	
	auto platformUrl {"http://localhost:9111"};
	
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
