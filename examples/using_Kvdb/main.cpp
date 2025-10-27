#include <optional>
#include <iostream>
#include <thread>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/core/Events.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>


using namespace privmx::endpoint;
int main() {
	// the values below should be replaced by the ones corresponding to your Brigde Server instance.
        auto platformUrl {"<YOUR_BRIDGE_URL_HERE>"};
        auto solutionId {"<YOUR_SOLUTION_ID_HERE>"};
        auto contextId {"<YOUR_CONTEXT_ID_HERE>"};

        auto userId {"<YOUR_USER_ID_HERE>"};
        auto userPubKey {"<YOUR_USER_PUB_KEY_HERE>"};
        auto userPrivKey {"<YOUR_USER_PRIV_KEY_HERE>"};

	std::vector<core::UserWithPubKey> kvdbUsers;
	kvdbUsers.push_back({.userId = userId, .pubKey = userPubKey});
	
	// initialize Endpoint connection and Kvdbs API
	auto connection {core::Connection::connect(userPrivKey, solutionId, platformUrl)};
	auto kvdbApi {kvdb::KvdbApi::create(connection)};
	// start event listener
	core::EventQueue eventQueue {core::EventQueue::getInstance()};
	std::thread t([&](){
		while(true) {
			core::EventHolder event = eventQueue.waitEvent();
			std::cout << "onEvent: " << event.type() << std::endl;
			std::cout << event.toJSON() << std::endl;
			if(core::Events::isLibBreakEvent(event)) {
				// way to stop Event listener
				break;
			}
		}
	});
	t.detach();
	// subscribe for kvdbs general events
	kvdbApi.subscribeForKvdbEvents();

	//create Kvdb
	auto kvdbId {kvdbApi.createKvdb(
		contextId, 
		kvdbUsers, 
		kvdbUsers, 
		core::Buffer::from("some kvdb's public meta-data"), 
		core::Buffer::from("some kvdb's private meta-data")
	)};
	// get Kvdb
	auto kvdb = kvdbApi.getKvdb(
		kvdbId
	);
	// subscribe for particular kvdb events
	kvdbApi.subscribeForEntryEvents(kvdbId);
	//Update Kvdb
	kvdbApi.updateKvdb(
		kvdbId, 
		kvdbUsers, 
		kvdbUsers, 
		core::Buffer::from("some other kvdb's public meta-data"), 
		kvdb.privateMeta,
		kvdb.version,
		false,
		false
	);
	// create entry to kvdb
	std::string entry_key {"entry key"};
	kvdbApi.setEntry(
		kvdbId, 
		entry_key,
		core::Buffer::from("some public meta-data"), 
		core::Buffer::from("some private meta-data"),
		core::Buffer::from("entry_data"),
		0
	);
	// read created entry
	auto entry {kvdbApi.getEntry(
		kvdbId,
		entry_key
	)};
	// update created entry 
	kvdbApi.setEntry(
		kvdbId, 
		"entry key",
		entry.privateMeta, 
		entry.privateMeta,
		core::Buffer::from("new_entry_data"),
		entry.version
	);
	// get kvdb's entries Keys
	auto entriesKeys {kvdbApi.listEntriesKeys(
    	kvdbId,
		core::PagingQuery{
			.skip=0, 
			.limit=100, 
			.sortOrder="desc"
		}
	)};

	std::cout << "All entries key in Kvdb: " << std::endl;
	for (auto keys: entriesKeys.readItems) {
		std::cout << "key: " << keys << std::endl;
	}
	return 0;
}
