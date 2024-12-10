#include "privmx/endpoint/programs/benchmark/PrepereInitData.hpp"
#include <iostream>
using namespace privmx::endpoint;

std::vector<std::string> PrepareInitDataThread(
    std::shared_ptr<core::Connection> connection, 
    std::shared_ptr<thread::ThreadApi> threadApi, 
    std::shared_ptr<store::StoreApi> storeApi, 
    std::shared_ptr<inbox::InboxApi> inboxApi,
    std::string userId,
    std::string userPubKey,
    uint64_t fun_number
)  {
    std::vector<std::string> result;
    result.push_back(userId);
    result.push_back(userPubKey);
    switch(fun_number) {
        case 0x00010000 :
        case 0x00010001 :
        case 0x00010002 :
        case 0x00010003 :
        case 0x00010004 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            result.push_back(
                threadApi->createThread(
                    contextId,
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                )
            );
            return result;
        }
        case 0x00010005 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            result.push_back(
                threadApi->createThread(
                    contextId,
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                )
            );
            std::string msg_data = "t";
            for(int i = 0; i < 10; i++) {
                msg_data.append(msg_data);
            }
            result.push_back(msg_data);
            return result;
        }
        case 0x00010006 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            result.push_back(
                threadApi->createThread(
                    contextId,
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                )
            );
            std::string msg_data = "t";
            for(int i = 0; i < 12; i++) {
                msg_data.append(msg_data);
            }
            result.push_back(msg_data);
            return result;
        }
        case 0x00020000 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            auto threadId = threadApi->createThread(
                contextId,
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                core::Buffer::from("public"),
                core::Buffer::from("private")
            );
            result.push_back(
                threadApi->sendMessage(
                    threadId,
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    core::Buffer::from("data")
                )
            );
            return result;
        }
        case 0x00020001 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            auto threadId = threadApi->createThread(
                contextId,
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                core::Buffer::from("public"),
                core::Buffer::from("private")
            );
            std::string data = "t";
            for(int i = 0; i < 10; i++) {
                data.append(data);
            }
            result.push_back(
                threadApi->sendMessage(
                    threadId,
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    core::Buffer::from(data)
                )
            );
            return result;
        }
        case 0x00020002 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            auto threadId = threadApi->createThread(
                contextId,
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                core::Buffer::from("public"),
                core::Buffer::from("private")
            );
            std::string data = "t";
            for(int i = 0; i < 12; i++) {
                data.append(data);
            }
            result.push_back(
                threadApi->sendMessage(
                    threadId,
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    core::Buffer::from(data)
                )
            );
            return result;
        }
        case 0x00000000 :
        case 0x00000001 :
        case 0x00000002 :
        case 0x00000003 :
        case 0x00000004 :
        default : {
            result.push_back(connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId);
            return result;
        }
    }
    return result;
}

std::vector<std::string> PrepareInitDataStore(
    std::shared_ptr<core::Connection> connection, 
    std::shared_ptr<thread::ThreadApi> threadApi, 
    std::shared_ptr<store::StoreApi> storeApi, 
    std::shared_ptr<inbox::InboxApi> inboxApi,
    std::string userId,
    std::string userPubKey,
    uint64_t fun_number
) {
    std::vector<std::string> result;
    result.push_back(userId);
    result.push_back(userPubKey);
    switch(fun_number) {
        case 0x00010000 :
        case 0x00010001 :
        case 0x00010002 :
        case 0x00010003 :
        case 0x00010004 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            result.push_back(
                storeApi->createStore(
                    contextId,
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                )
            );
            return result;
        }
        case 0x00010005 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            result.push_back(
                storeApi->createStore(
                    contextId,
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                )
            );
            std::string file_data = "s";
            for(int i = 0; i < 20; i++) {
                file_data.append(file_data);
            }
            result.push_back(file_data);
            return result;
        }
        case 0x00010006 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            result.push_back(
                storeApi->createStore(
                    contextId,
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private")
                )
            );
            std::string file_data = "s";
            for(int i = 0; i < 23; i++) {
                file_data.append(file_data);
            }
            result.push_back(file_data);
            return result;
        }
        case 0x00020000 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            auto storeId = storeApi->createStore(
                contextId,
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                core::Buffer::from("public"),
                core::Buffer::from("private")
            );
            auto handle = storeApi->createFile(
                storeId,
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                0
            );
            result.push_back(
                storeApi->closeFile(handle)
            );
            return result;
        }
        case 0x00020001 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            auto storeId = storeApi->createStore(
                contextId,
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                core::Buffer::from("public"),
                core::Buffer::from("private")
            );
            auto handle = storeApi->createFile(
                storeId,
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                1024*1024
            );
            std::string data = "s";
            for(int i = 0; i < 20; i++) {
                data.append(data);
            }
            storeApi->writeToFile(
                handle,
                core::Buffer::from(data)
            );
            result.push_back(
                storeApi->closeFile(handle)
            );
            return result;
        }
        case 0x00020002 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            auto storeId = storeApi->createStore(
                contextId,
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                core::Buffer::from("public"),
                core::Buffer::from("private")
            );
            auto handle = storeApi->createFile(
                storeId,
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                1024*1024*8
            );
            std::string data = "s";
            for(int i = 0; i < 23; i++) {
                data.append(data);
            }
            storeApi->writeToFile(
                handle,
                core::Buffer::from(data)
            );
            result.push_back(
                storeApi->closeFile(handle)
            );
            return result;
        }
        case 0x00000000 :
        case 0x00000001 :
        case 0x00000002 :
        case 0x00000003 :
        case 0x00000004 :
        default : {
            result.push_back(connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId);
            return result;
        }
    }
    return result;
}

std::vector<std::string> PrepareInitDataInbox(
    std::shared_ptr<core::Connection> connection, 
    std::shared_ptr<thread::ThreadApi> threadApi, 
    std::shared_ptr<store::StoreApi> storeApi, 
    std::shared_ptr<inbox::InboxApi> inboxApi,
    std::string userId,
    std::string userPubKey,
    uint64_t fun_number
) {
    std::vector<std::string> result;
    result.push_back(userId);
    result.push_back(userPubKey);
    switch(fun_number) {
        case 0x00010000 :
        case 0x00010001 :
        case 0x00010002 :
        case 0x00010003 :
        case 0x00010004 :
        case 0x00010005 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            result.push_back(
                inboxApi->createInbox(
                    contextId,
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    std::nullopt
                )
            );
            return result;
        }
        case 0x00010006 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            result.push_back(
                inboxApi->createInbox(
                    contextId,
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                        .userId=userId,
                        .pubKey=userPubKey
                    }},
                    core::Buffer::from("public"),
                    core::Buffer::from("private"),
                    std::nullopt
                )
            );
            std::string file_data = "s";
            for(int i = 0; i < 20; i++) {
                file_data.append(file_data);
            }
            result.push_back(file_data);
            return result;
        }
        case 0x00020000 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            auto inboxId = inboxApi->createInbox(
                contextId,
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                std::nullopt
            );
            auto handle = inboxApi->prepareEntry(
                inboxId,
                core::Buffer::from("data"),
                {},
                std::nullopt
            );
            inboxApi->sendEntry(handle);
            result.push_back(
                inboxApi->listEntries(
                    inboxId,
                    {
                        .skip=0, 
                        .limit=1, 
                        .sortOrder="desc"
                    }
                ).readItems[0].entryId
            );
            return result;
        }
        case 0x00020001 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            auto inboxId = inboxApi->createInbox(
                contextId,
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                std::nullopt
            );
            auto filehandle_0 = inboxApi->createFileHandle(
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                0
            );
            auto filehandle_1 = inboxApi->createFileHandle(
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                0
            );
            auto filehandle_2 = inboxApi->createFileHandle(
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                0
            );
            auto filehandle_3 = inboxApi->createFileHandle(
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                0
            );
            auto filehandle_4 = inboxApi->createFileHandle(
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                0
            );


            auto handle = inboxApi->prepareEntry(
                inboxId,
                core::Buffer::from("data"),
                {filehandle_0, filehandle_1, filehandle_2, filehandle_3, filehandle_4},
                std::nullopt
            );
            inboxApi->sendEntry(handle);
            result.push_back(
                inboxApi->listEntries(
                    inboxId,
                    {
                        .skip=0, 
                        .limit=1, 
                        .sortOrder="desc"
                    }
                ).readItems[0].entryId
            );
            return result;
        }
        case 0x00020002 : {
            auto contextId = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId;
            auto inboxId = inboxApi->createInbox(
                contextId,
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                std::vector<core::UserWithPubKey>{core::UserWithPubKey{
                    .userId=userId,
                    .pubKey=userPubKey
                }},
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                std::nullopt
            );
            std::string data = "s";
            for(int i = 0; i < 20; i++) {
                data.append(data);
            }
            auto filehandle_0 = inboxApi->createFileHandle(
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                1024*1024
            );
            auto filehandle_1 = inboxApi->createFileHandle(
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                1024*1024
            );
            auto filehandle_2 = inboxApi->createFileHandle(
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                1024*1024
            );
            auto filehandle_3 = inboxApi->createFileHandle(
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                1024*1024
            );
            auto filehandle_4 = inboxApi->createFileHandle(
                core::Buffer::from("public"),
                core::Buffer::from("private"),
                1024*1024
            );
            auto handle = inboxApi->prepareEntry(
                inboxId,
                core::Buffer::from("data"),
                {filehandle_0, filehandle_1, filehandle_2, filehandle_3, filehandle_4},
                std::nullopt
            );
            inboxApi->writeToFile(
                handle,
                filehandle_0,
                core::Buffer::from(data)
            );
            inboxApi->writeToFile(
                handle,
                filehandle_1,
                core::Buffer::from(data)
            );
            inboxApi->writeToFile(
                handle,
                filehandle_2,
                core::Buffer::from(data)
            );
            inboxApi->writeToFile(
                handle,
                filehandle_3,
                core::Buffer::from(data)
            );
            inboxApi->writeToFile(
                handle,
                filehandle_4,
                core::Buffer::from(data)
            );
            inboxApi->sendEntry(handle);
            result.push_back(
                inboxApi->listEntries(
                    inboxId,
                    {
                        .skip=0, 
                        .limit=1, 
                        .sortOrder="desc"
                    }
                ).readItems[0].entryId
            );
            return result;
        }
        case 0x00000000 :
        case 0x00000001 :
        case 0x00000002 :
        case 0x00000003 :
        case 0x00000004 :
        default : {
            result.push_back(connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"}).readItems[0].contextId);
            return result;
        }
    }
    return result;
}


std::vector<std::string> PrepareInitDataCrypto(
    std::shared_ptr<core::Connection> connection, 
    std::shared_ptr<thread::ThreadApi> threadApi, 
    std::shared_ptr<store::StoreApi> storeApi, 
    std::shared_ptr<inbox::InboxApi> inboxApi,
    std::string userId,
    std::string userPubKey,
    uint64_t fun_number
) {
    std::vector<std::string> result;
    switch(fun_number) {
        case 0x00000000:
        case 0x00000001: {
                std::string data = "c";
                for(int i = 0; i < 10; i++) {
                    data.append(data);
                }
                result.push_back(data);
            }
            break;
        case 0x00000002:
        case 0x00000003: {
                std::string data = "c";
                for(int i = 0; i < 15; i++) {
                    data.append(data);
                }
                result.push_back(data);
            }
            break;
        case 0x00000004: 
        case 0x00000005: {
                std::string data = "c";
                for(int i = 0; i < 20; i++) {
                    data.append(data);
                }
                result.push_back(data);
            }
            break; 
    }
    return result;
}

std::vector<std::string> PrepareInitData(
    std::shared_ptr<core::Connection> connection, 
    std::shared_ptr<thread::ThreadApi> threadApi, 
    std::shared_ptr<store::StoreApi> storeApi, 
    std::shared_ptr<inbox::InboxApi> inboxApi,
    std::string userId,
    std::string userPubKey,
    Module module, 
    uint64_t fun_number
) {
    switch(module) {
        case Module::thread:
            return PrepareInitDataThread(connection, threadApi, storeApi, inboxApi, userId, userPubKey, fun_number);
        case Module::store:
            return PrepareInitDataStore(connection, threadApi, storeApi, inboxApi, userId, userPubKey, fun_number);
        case Module::inbox:
            return PrepareInitDataInbox(connection, threadApi, storeApi, inboxApi, userId, userPubKey, fun_number);
        case Module::crypto:
            return PrepareInitDataCrypto(connection, threadApi, storeApi, inboxApi, userId, userPubKey, fun_number);
    }
    std::cout << "Module not found" << std::endl;
    throw "Module not found";
     
}