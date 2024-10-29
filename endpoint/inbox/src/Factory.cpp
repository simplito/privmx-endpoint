#include "privmx/endpoint/inbox/Factory.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

store::server::FileDefinition Factory::createStoreFileDefinition(const uint64_t& fileSize, const uint64_t& checksumSize) {
    auto model {Factory::createObject<store::server::FileDefinition>()};
    model.size(fileSize);
    model.checksumSize(checksumSize);
    return model;
}

inbox::server::InboxFile Factory::createInboxFile(const Poco::Int64& fileIndex, const Poco::Dynamic::Var& meta) {
    auto model {Factory::createObject<inbox::server::InboxFile>()};
    model.fileIndex(fileIndex);
    model.meta(meta);
    return model;
}

store::server::StoreFileGetModel Factory::createStoreFileGetModel(const std::string& fileId) {
    auto model {Factory::createObject<store::server::StoreFileGetModel>()};
    model.fileId(fileId);
    return model;
}

store::server::StoreFileGetManyModel Factory::createStoreFileGetManyModel(const std::string& storeId, const std::vector<std::string>& filesIds, const bool failOnError) {
    auto listModel {Factory::createList<std::string>()};
    for (auto id : filesIds) {
        listModel.add(id);
    }
    auto model {Factory::createObject<store::server::StoreFileGetManyModel>()};
    model.failOnError(failOnError);
    model.fileIds(listModel);
    model.storeId(storeId);
    return model;
}
