
#include <iostream>
#include <thread>
#include <vector>

#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/event/Events.hpp>

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
			if (event::Events::isContextCustomEvent(event)) {
				auto customEvent = event::Events::extractContextCustomEvent(event);
				std::cout << "Received event:" << std::endl;
				std::cout << "contextId: " << customEvent.data.contextId << std::endl;
				std::cout << "sender: " << customEvent.data.userId << std::endl;
				std::cout << "payload: " << customEvent.data.payload.stdString() << std::endl;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
	});

	// initialize Endpoint connection and Event API
	auto connection {core::Connection::connect(USER1_PRIVATE_KEY, SOLUTION_ID, BRIDGE_URL)};
	auto eventApi {event::EventApi::create(connection)};

	// Subscribe for the Thread's events
	eventApi.subscribeForCustomEvents(CONTEXT_ID, "myChannel");

	// sending event to myself
	std::vector<core::UserWithPubKey> recipients {
		{.userId = USER1_ID, .pubKey = USER1_PUBLIC_KEY}
	};

	// Emit event
	eventApi.emitEvent(
		CONTEXT_ID, 
		recipients, 
		"myChannel", 
		core::Buffer::from("some data")
	);

	t.join();
	
	return 0;
}
