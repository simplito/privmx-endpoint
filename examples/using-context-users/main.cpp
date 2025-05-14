
#include <iostream>
#include <thread>
#include <vector>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Buffer.hpp>

using namespace privmx::endpoint;

int main(int argc, char* argv[]) {
	// the values below should be replaced by the ones corresponding to your Brigde Server instance.
	auto BRIDGE_URL {"http://localhost:9111"};
	auto SOLUTION_ID {"924d3b49-5206-43ab-a1cc-7539e0b9977d"};
	auto CONTEXT_ID {"5319f785-9a45-4614-a638-e47b5152b610"};
	
	auto USER1_ID {"user1"};
	auto USER1_PUBLIC_KEY {"51WPnnGwztNPWUDEbhncYDxZCZWAFS4M9Yqv94N2335nL92fEn"};
	auto USER1_PRIVATE_KEY {"L3ycXibEzJm9t9swoJ4KtSmJsenHmmgRnYY79Q2TqfJMwTGaWfA7"};

	// initialize Endpoint connection
	auto connection {core::Connection::connect(USER1_PRIVATE_KEY, SOLUTION_ID, BRIDGE_URL)};

	// Get users of the Context
	auto contextUsers {connection.getContextUsers(CONTEXT_ID)};
	for (auto ctxUser: contextUsers) {
		std::cout << "UserId: " << ctxUser.user.userId << " / UserPubKey: " << ctxUser.user.pubKey << std::endl;
		std::cout << "isActive: " << ctxUser.isActive << std::endl; 
	}
	return 0;
}
