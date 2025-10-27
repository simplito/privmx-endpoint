
#include <iostream>
#include <thread>
#include <vector>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Buffer.hpp>

using namespace privmx::endpoint;

int main(int argc, char* argv[]) {
	// the values below should be replaced by the ones corresponding to your Brigde Server instance.
        auto BRIDGE_URL {"<YOUR_BRIDGE_URL_HERE>"};
        auto SOLUTION_ID {"<YOUR_SOLUTION_ID_HERE>"};
        auto CONTEXT_ID {"<YOUR_CONTEXT_ID_HERE>"};

        auto USER1_ID {"<YOUR_USER_ID_HERE>"};
        auto USER1_PUBLIC_KEY {"<YOUR_USER_PUB_KEY_HERE>"};
        auto USER1_PRIVATE_KEY {"<YOUR_USER_PRIV_KEY_HERE>"};

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
