#include "privmx/endpoint/inbox/InboxDataHelper.hpp"
using namespace privmx::endpoint;
using namespace privmx::endpoint::inbox;

std::string InboxDataHelper::serializeEncKey(const privmx::endpoint::core::EncKey& encKey) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    obj->set("id", encKey.id);
    obj->set("key", encKey.key);
    return utils::Base64::from(utils::Utils::stringify(obj));
}

privmx::endpoint::core::EncKey InboxDataHelper::deserializeEncKey(const std::string& serializedKey) {
    auto obj {utils::Utils::parseJsonObject(utils::Base64::toString(serializedKey))};
    return {.id = obj->get("id"), .key = obj->get("key")};
}

std::string InboxDataHelper::getRandomName() {
    return utils::Base64::from(crypto::Crypto::randomBytes(8));
}

server::FileConfig InboxDataHelper::fileConfigToTypedObject(const FilesConfig& fileConfig) {
    auto result = Factory::createObject<server::FileConfig>();
    result.minCount(fileConfig.minCount);
    result.maxCount(fileConfig.maxCount);
    result.maxFileSize(fileConfig.maxFileSize);
    result.maxWholeUploadSize(fileConfig.maxWholeUploadSize);
    return result;
}

FilesConfig InboxDataHelper::fileConfigFromTypedObject(const server::FileConfig& fileConfig) {
    return {
        .minCount = fileConfig.minCount(),
        .maxCount = fileConfig.maxCount(),
        .maxFileSize = fileConfig.maxFileSize(),
        .maxWholeUploadSize = fileConfig.maxWholeUploadSize()
    };
}

privmx::utils::List<std::string> InboxDataHelper::mapUsers(const std::vector<core::UserWithPubKey>& users) {
    auto result = Factory::createList<std::string>();
    for (auto user : users) {
        result.add(user.userId);
    }
    return result;
}