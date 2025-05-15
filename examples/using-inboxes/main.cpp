#include <optional>
#include <iostream>
#include <thread>
#include <vector>
#include <string_view>
#include <algorithm>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
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

	auto connection {core::Connection::connect(USER1_PRIVATE_KEY, SOLUTION_ID, BRIDGE_URL)};
	auto threadApi {thread::ThreadApi::create(connection)};
	auto storeApi {store::StoreApi::create(connection)};
	auto inboxApi {inbox::InboxApi::create(connection, threadApi, storeApi)};

	core::PagingQuery defaultListQuery = {.skip = 0, .limit = 10, .sortOrder = "desc"};
	std::vector<core::UserWithPubKey> managers {
		{.userId = USER1_ID, .pubKey = USER1_PUBLIC_KEY}
	};

	std::vector<core::UserWithPubKey> users {
		{.userId = USER1_ID, .pubKey = USER1_PUBLIC_KEY}
	};

	std::string privateMeta = R"({"name": "Album"})";
	std::string publicMeta = R"(
	    {
			"formScheme": [
                {"question":"Your name"},
                {"question":"E-mail"}
            ]
    	}
	)";
    

	// create a new Inbox with access for USER_1 as manager and USER_2 as regular user
	auto inboxId {inboxApi.createInbox(
		CONTEXT_ID, 
		users, managers, 
		core::Buffer::from(publicMeta), 
		core::Buffer::from(privateMeta),
		std::nullopt
	)};

	// auto inboxId {"68078618c34be32ff95cfd01"};
	std::cout << "InboxId: " << inboxId << std::endl;

	// fetching Inboxes
	auto inboxesList {inboxApi.listInboxes(CONTEXT_ID, defaultListQuery)};
	for (auto inbox: inboxesList.readItems) {
		std::cout << "InboxId: " << inbox.inboxId << std::endl;
	}

	// Getting a single Inbox
	auto currentInbox {inboxApi.getInbox(inboxId)};

	// update a new Inbox with access for USER_1 as the only user.
	inboxApi.updateInbox(
		inboxId, 
		users, managers,
		currentInbox.publicMeta, 
		currentInbox.privateMeta,
		currentInbox.filesConfig,
		currentInbox.version, // <- pass the version of the Inbox you will perform the update on
		false, // <- force update (without checking version)
		false // <- force to regenerate a key for the Store
	);

	// Public access to Inbox - sending entries
	auto publicConnection {core::Connection::connectPublic(SOLUTION_ID, BRIDGE_URL)};
	auto threadPubApi {thread::ThreadApi::create(publicConnection)};
	auto storePubApi {store::StoreApi::create(publicConnection)};
	auto inboxPubApi {inbox::InboxApi::create(publicConnection, threadPubApi, storePubApi)};

	// Reading Inbox' Public View
	auto publicView {inboxPubApi.getInboxPublicView(inboxId)};
	std::cout << "Public view: " << publicView.publicMeta.stdString() << std::endl;

	// Adding a simple entry (without files)
	auto entryHandle {inboxPubApi.prepareEntry(inboxId, core::Buffer::from("sample data"))};
	inboxPubApi.sendEntry(entryHandle);

	// Adding the entry with files
	std::vector<int64_t>files{};
	auto sampleData {core::Buffer::from("some file sample data")};
	auto fileHandle {inboxPubApi.createFileHandle(core::Buffer::from(""), core::Buffer::from(""), sampleData.size())};	
	files.push_back(fileHandle);

	auto entryHandle2 {inboxPubApi.prepareEntry(inboxId, core::Buffer::from("sample data"), files)};
	inboxPubApi.writeToFile(entryHandle2, fileHandle, sampleData);
	inboxPubApi.sendEntry(entryHandle2);


	// fetching entries
	auto entriesList {inboxApi.listEntries(inboxId, defaultListQuery)};
	for (auto entry: entriesList.readItems) {
		std::cout << "EntryId: " << entry.entryId << " / data: " << entry.data.stdString() << std::endl;
	}

	// reading entries containing files
	for (auto entry: entriesList.readItems) {
		std::cout << "EntryId: " << entry.entryId << " / data: " << entry.data.stdString() << std::endl;

		for (auto file: entry.files) {
			auto fh {inboxApi.openFile(file.info.fileId)};
			auto data {inboxApi.readFromFile(fh, file.size)};
			std::cout << "File data: " << data.stdString() << std::endl;
		}
	}

	return 0;
}
