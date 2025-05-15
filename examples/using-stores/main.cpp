#include <optional>
#include <iostream>
#include <thread>
#include <vector>
#include <string_view>
#include <algorithm>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
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
	auto storeApi {store::StoreApi::create(connection)};

	core::PagingQuery defaultListQuery = {.skip = 0, .limit = 10, .sortOrder = "desc"};
	std::vector<core::UserWithPubKey> managers {
		{.userId = USER1_ID, .pubKey = USER1_PUBLIC_KEY}
	};

	std::vector<core::UserWithPubKey> users {
		{.userId = USER1_ID, .pubKey = USER1_PUBLIC_KEY}
	};

	// create a new Store with access for USER_1 as manager and USER_2 as regular user
	auto storeId {storeApi.createStore(
		CONTEXT_ID, 
		users, managers, 
		core::Buffer::from("some Store's public meta-data"), 
		core::Buffer::from("some Store's private meta-data")
	)};

	// // fetching stores
	auto storesList {storeApi.listStores(CONTEXT_ID, defaultListQuery)};

	// // Getting a single Store
	auto currentStore {storeApi.getStore(storeId)};

	// // update a new Store with access for USER_1 as the only user.
	storeApi.updateStore(
		storeId, 
		users, managers,
		currentStore.publicMeta, 
		currentStore.privateMeta,
		currentStore.version, // <- pass the version of the Store you will perform the update on
		false, // <- force update (without checking version)
		false // <- force to regenerate a key for the Store
	);


	// Uploading a file
	auto STORE_ID {"6804115a60b35d1b5d549087"};

	auto sampleData {core::Buffer::from("some sample data")};
	auto fh {storeApi.createFile(STORE_ID, core::Buffer::from(""), core::Buffer::from(""), sampleData.size())};	
	storeApi.writeToFile(fh, sampleData);
	storeApi.closeFile(fh);

	// List of files
	auto filesList {storeApi.listFiles(STORE_ID, defaultListQuery)};
	for (auto file: filesList.readItems) {
		std::cout << "FileId: " << file.info.fileId << std::endl;
	}

	auto lastFile {filesList.readItems[0]};

	// Reading file
	auto readHandle {storeApi.openFile(lastFile.info.fileId)};
	core::Buffer read {storeApi.readFromFile(readHandle, lastFile.size)};
	std::cout << read.stdString() << std::endl;

	// Update file info
	storeApi.updateFileMeta(
		lastFile.info.fileId, 
		core::Buffer::from("new public meta"), 
		lastFile.privateMeta
	);

	// update file data
	auto fileNewData {core::Buffer::from("some new data")};

	auto updateHandle {storeApi.updateFile(
		lastFile.info.fileId,
		lastFile.publicMeta,
		lastFile.privateMeta,
		fileNewData.size()
	)};	
	storeApi.writeToFile(updateHandle, fileNewData);
	storeApi.closeFile(updateHandle);

	return 0;
}
