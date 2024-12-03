#include "privmx/endpoint/programs/benchmark/GetTestFunction.hpp"

using namespace privmx::endpoint;

std::function<
    void(
        std::shared_ptr<core::Connection>, 
        std::shared_ptr<thread::ThreadApi>, 
        std::shared_ptr<store::StoreApi>, 
        std::shared_ptr<inbox::InboxApi>, 
        const std::vector<std::string>&
    )
> GetTestFunctionThread(uint64_t fun_number) {
    switch(fun_number) {
        case 0x00000000:
            // create
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                threadApi->createThread(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                );
            });
        case 0x00000001:
            // create + get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto threadId = threadApi->createThread(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                );
                threadApi->getThread(threadId);
            });
        case 0x00000002:
            // create + get + delete
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto threadId = threadApi->createThread(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                );
                threadApi->getThread(threadId);
                threadApi->deleteThread(threadId);
            });
        case 0x00000003:
            // create + list 100 
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto threadId = threadApi->createThread(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                );
                threadApi->listThreads(
                    data[2],
                    {
                        .skip=0, 
                        .limit=100, 
                        .sortOrder="desc"
                    }
                );
            });
        case 0x00000004:
            // create + update + get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto threadId = threadApi->createThread(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                );
                threadApi->updateThread(
                    threadId,
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    1,
                    true,
                    true
                );
                threadApi->getThread(threadId);
            });
        case 0x00010000:
            // sendMessage
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                threadApi->sendMessage(
                    data[2],
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    core::Buffer::from("data")
                );
            });
        case 0x00010001:
            // sendMessage + get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto messageId = threadApi->sendMessage(
                    data[2],
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    core::Buffer::from("data")
                );
                threadApi->getMessage(messageId);
            });
        case 0x00010002:
            // sendMessage + get + delete
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto messageId = threadApi->sendMessage(
                    data[2],
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    core::Buffer::from("data")
                );
                threadApi->getMessage(messageId);
                threadApi->deleteMessage(messageId);
            });
        case 0x00010003:
            // sendMessage + list
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto messageId = threadApi->sendMessage(
                    data[2],
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    core::Buffer::from("data")
                );
                threadApi->listMessages(
                    data[2],
                    {
                        .skip=0, 
                        .limit=100, 
                        .sortOrder="desc"
                    }
                );
            });
        case 0x00010004:
            // sendMessage + update + get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto messageId = threadApi->sendMessage(
                    data[2],
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    core::Buffer::from("data")
                );
                threadApi->updateMessage(
                    messageId,
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    core::Buffer::from("data")
                );
                threadApi->getMessage(messageId);
            });
        case 0x00020000:
        case 0x00020001:
        case 0x00020002:
            // get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                threadApi->getMessage(
                    data[2]
                );
            });
        
    }
    throw "not found";
}

std::function<
    void(
        std::shared_ptr<core::Connection>, 
        std::shared_ptr<thread::ThreadApi>, 
        std::shared_ptr<store::StoreApi>, 
        std::shared_ptr<inbox::InboxApi>, 
        const std::vector<std::string>&
    )
> GetTestFunctionStore(uint64_t fun_number) {
    switch(fun_number) {
        case 0x00000000:
            // create
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                storeApi->createStore(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                );
            });
        case 0x00000001:
            // create + get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto storeId = storeApi->createStore(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                );
                storeApi->getStore(storeId);
            });
        case 0x00000002:
            // create + get + delete
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto storeId = storeApi->createStore(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                );
                storeApi->getStore(storeId);
                storeApi->deleteStore(storeId);
            });
        case 0x00000003:
            // create + list 100 
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto storeId = storeApi->createStore(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                );
                storeApi->listStores(
                    data[2],
                    {
                        .skip=0, 
                        .limit=100, 
                        .sortOrder="desc"
                    }
                );
            });
        case 0x00000004:
            // create + update + get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto storeId = storeApi->createStore(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                );
                storeApi->updateStore(
                    storeId,
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    1,
                    true,
                    true
                );
                storeApi->getStore(storeId);
            });
        case 0x00010000:
            // create
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto handle = storeApi->createFile(
                    data[2],
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    4
                );
                storeApi->writeToFile(handle, core::Buffer::from("test"));
                storeApi->closeFile(handle);
            });
        case 0x00010001:
            // create + get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto handle = storeApi->createFile(
                    data[2],
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    4
                );
                storeApi->writeToFile(handle, core::Buffer::from("test"));
                auto fileId = storeApi->closeFile(handle);
                storeApi->getFile(fileId);
            });
        case 0x00010002:
            // create + get + delete
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto handle = storeApi->createFile(
                    data[2],
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    4
                );
                storeApi->writeToFile(handle, core::Buffer::from("test"));
                auto fileId = storeApi->closeFile(handle);
                storeApi->getFile(fileId);
                storeApi->deleteFile(fileId);
            });
        case 0x00010003:
            // create + list
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto handle = storeApi->createFile(
                    data[2],
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    4
                );
                storeApi->writeToFile(handle, core::Buffer::from("test"));
                storeApi->closeFile(handle);
                storeApi->listFiles(
                    data[2],
                    {
                        .skip=0, 
                        .limit=100, 
                        .sortOrder="desc"
                    }
                );
            });
        case 0x00010004:
            // create + update + get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto handle = storeApi->createFile(
                    data[2],
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    4
                );
                storeApi->writeToFile(handle, core::Buffer::from("test"));
                auto fileId = storeApi->closeFile(handle);

                auto handle_2 = storeApi->updateFile(
                    fileId,
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    5
                );
                storeApi->writeToFile(handle_2, core::Buffer::from("test2"));
                storeApi->closeFile(handle_2);

                storeApi->getFile(fileId);
            });
        case 0x00020000:
        case 0x00020001:
        case 0x00020002:
            // get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                storeApi->getFile(
                    data[2]
                );
            });
    }
    throw "not found";
}

std::function<
    void(
        std::shared_ptr<core::Connection>, 
        std::shared_ptr<thread::ThreadApi>, 
        std::shared_ptr<store::StoreApi>, 
        std::shared_ptr<inbox::InboxApi>, 
        const std::vector<std::string>&
    )
> GetTestFunctionInbox(uint64_t fun_number) {
    switch(fun_number) {
        case 0x00000000:
            // create
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                inboxApi->createInbox(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    std::nullopt
                );
            });
        case 0x00000001:
            // create + get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto inboxId = inboxApi->createInbox(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    std::nullopt
                );
                inboxApi->getInbox(inboxId);
            });
        case 0x00000002:
            // create + get + delete
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto inboxId = inboxApi->createInbox(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    std::nullopt
                );
                inboxApi->getInbox(inboxId);
                inboxApi->deleteInbox(inboxId);
            });
        case 0x00000003:
            // create + list 100 
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto inboxId = inboxApi->createInbox(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    std::nullopt
                );
                inboxApi->listInboxes(
                    data[2],
                    {
                        .skip=0, 
                        .limit=100, 
                        .sortOrder="desc"
                    }
                );
            });
        case 0x00000004:
            // create + update + get
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto inboxId = inboxApi->createInbox(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    std::nullopt
                );
                inboxApi->updateInbox(
                    data[2],
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=data[0],
                        .pubKey=data[1]
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    std::nullopt,
                    1,
                    true,
                    true
                );
                inboxApi->getInbox(inboxId);
            });
        case 0x00010000:
            // create
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto handle = inboxApi->prepareEntry(
                    data[2],
                    core::Buffer::from("text"),
                    {},
                    std::nullopt
                );
                inboxApi->sendEntry(handle);
            });
        case 0x00010001:
            // create + list 1
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto handle = inboxApi->prepareEntry(
                    data[2],
                    core::Buffer::from("text"),
                    {},
                    std::nullopt
                );
                inboxApi->sendEntry(handle);
                inboxApi->listEntries(
                    data[2],
                    {
                        .skip=0, 
                        .limit=1, 
                        .sortOrder="desc"
                    }
                );
            });
        case 0x00010002:
            // create + list 1 + delete
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto handle = inboxApi->prepareEntry(
                    data[2],
                    core::Buffer::from("text"),
                    {},
                    std::nullopt
                );
                inboxApi->sendEntry(handle);
                auto entries = inboxApi->listEntries(
                    data[2],
                    {
                        .skip=0, 
                        .limit=1, 
                        .sortOrder="desc"
                    }
                );
                inboxApi->deleteEntry(entries.readItems[0].entryId);
            });
        case 0x00010003:
            // create + list 100
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto handle = inboxApi->prepareEntry(
                    data[2],
                    core::Buffer::from("text"),
                    {},
                    std::nullopt
                );
                inboxApi->sendEntry(handle);
                auto entries = inboxApi->listEntries(
                    data[2],
                    {
                        .skip=0, 
                        .limit=100, 
                        .sortOrder="desc"
                    }
                );
            });
        case 0x00010004:
            // create + list 1 + update
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                auto handle = inboxApi->prepareEntry(
                    data[2],
                    core::Buffer::from("text"),
                    {},
                    std::nullopt
                );
                inboxApi->sendEntry(handle);
                auto entries = inboxApi->listEntries(
                    data[2],
                    {
                        .skip=0, 
                        .limit=1, 
                        .sortOrder="desc"
                    }
                );
                inboxApi->readEntry(entries.readItems[0].entryId);
            });
        case 0x00020000:
        case 0x00020001:
        case 0x00020002:
            // read
            return ([](std::shared_ptr<core::Connection> connection, std::shared_ptr<thread::ThreadApi> threadApi, std::shared_ptr<store::StoreApi> storeApi, std::shared_ptr<inbox::InboxApi> inboxApi, const std::vector<std::string>& data) {
                inboxApi->readEntry(
                    data[2]
                );
            });
    }
    throw "not found";
}

std::function<
    void(
        std::shared_ptr<privmx::endpoint::core::Connection>, 
        std::shared_ptr<privmx::endpoint::thread::ThreadApi>, 
        std::shared_ptr<privmx::endpoint::store::StoreApi>, 
        std::shared_ptr<privmx::endpoint::inbox::InboxApi>, 
        const std::vector<std::string>&
    )
> GetTestFunction(Module module, uint64_t fun_number) {
    switch(module) {
        case Module::thread:
            return GetTestFunctionThread(fun_number);
        case Module::store:
            return GetTestFunctionStore(fun_number);
        case Module::inbox:
            return GetTestFunctionInbox(fun_number);
    }
    throw "not found";
}