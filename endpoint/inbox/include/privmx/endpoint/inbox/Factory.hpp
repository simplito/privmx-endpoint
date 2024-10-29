#ifndef _PRIVMXLIB_ENDPOINT_INBOX_TYPEDOBJECTFACTORY_HPP_
#define _PRIVMXLIB_ENDPOINT_INBOX_TYPEDOBJECTFACTORY_HPP_

#include <string>
#include "privmx/utils/Utils.hpp"
#include "privmx/endpoint/inbox/ServerTypes.hpp"
#include "privmx/endpoint/inbox/Types.hpp"
#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"
#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <privmx/crypto/Crypto.hpp>

namespace privmx {
namespace endpoint {
namespace inbox {

class Factory {
public:
    static store::server::FileDefinition createStoreFileDefinition(const uint64_t& fileSize, const uint64_t& checksumSize);
    static store::server::StoreFileGetModel createStoreFileGetModel(const std::string& fileId);
    static store::server::StoreFileGetManyModel createStoreFileGetManyModel(const std::string& storeId, const std::vector<std::string>& filesIds, const bool failOnError);
    static inbox::server::InboxFile createInboxFile(const Poco::Int64& fileIndex, const Poco::Dynamic::Var& meta);

    template <typename T = utils::TypedObject>
    static T createObject() {
        return utils::TypedObjectFactory::createNewObject<T>();
    }

    template <typename T = utils::TypedObject>
    static T createObject(const Poco::Dynamic::Var &var) {
        return utils::TypedObjectFactory::createObjectFromVar<T>(var);
    }

    template <typename T = utils::TypedObject>
    static utils::List<T> createList() {
        return utils::TypedObjectFactory::createNewList<T>();
    }

    template <typename T = utils::TypedObject>
    static utils::List<T> createList(const Poco::Dynamic::Var &var) {
        return utils::TypedObjectFactory::createListFromVar<T>(var);
    }
};


}
}
}

#endif // _PRIVMXLIB_ENDPOINT_INBOX_TYPEDOBJECTFACTORY_HPP_
