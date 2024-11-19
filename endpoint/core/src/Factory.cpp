/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

Poco::Dynamic::Var Factory::createPolicyServerObject(const privmx::endpoint::core::ContainerPolicy& policy) {
    Poco::JSON::Object::Ptr model = new Poco::JSON::Object();
    if (policy.get.has_value()) {
        model->set("get", policy.get.value());
    }
    if (policy.update.has_value()) {
        model->set("update", policy.update.value());
    }
    if (policy.delete_.has_value()) {
        model->set("delete", policy.delete_.value());
    }
    if (policy.updatePolicy.has_value()) {
        model->set("updatePolicy", policy.updatePolicy.value());
    }
    if (policy.updaterCanBeRemovedFromManagers.has_value()) {
        model->set("updaterCanBeRemovedFromManagers", policy.updaterCanBeRemovedFromManagers.value());
    }
    if (policy.ownerCanBeRemovedFromManagers.has_value()) {
        model->set("ownerCanBeRemovedFromManagers", policy.ownerCanBeRemovedFromManagers.value());
    }
    if (policy.item.has_value()) {
        Poco::JSON::Object::Ptr itemModel = new Poco::JSON::Object();
        auto itemPolicy = policy.item.value();

        if (itemPolicy.get.has_value()) {
            itemModel->set("get", itemPolicy.get.value());
        }
        if (itemPolicy.listMy.has_value()) {
            itemModel->set("listMy", itemPolicy.listMy.value());
        }
        if (itemPolicy.listAll.has_value()) {
            itemModel->set("listAll", itemPolicy.listAll.value());
        }
        if (itemPolicy.create.has_value()) {
            itemModel->set("create", itemPolicy.create.value());
        }
        if (itemPolicy.update.has_value()) {
            itemModel->set("update", itemPolicy.update.value());
        }
        if (itemPolicy.delete_.has_value()) {
            itemModel->set("delete", itemPolicy.delete_.value());
        }
        
        model->set("item", itemModel);
    }

    return model;
}


Poco::Dynamic::Var Factory::createPolicyServerObject(const privmx::endpoint::core::ContainerPolicyWithoutItem& policy) {
    Poco::JSON::Object::Ptr model = new Poco::JSON::Object();
    if (policy.get.has_value()) {
        model->set("get", policy.get.value());
    }
    if (policy.update.has_value()) {
        model->set("update", policy.update.value());
    }
    if (policy.delete_.has_value()) {
        model->set("delete", policy.delete_.value());
    }
    if (policy.updatePolicy.has_value()) {
        model->set("updatePolicy", policy.updatePolicy.value());
    }
    if (policy.updaterCanBeRemovedFromManagers.has_value()) {
        model->set("updaterCanBeRemovedFromManagers", policy.updaterCanBeRemovedFromManagers.value());
    }
    if (policy.ownerCanBeRemovedFromManagers.has_value()) {
        model->set("ownerCanBeRemovedFromManagers", policy.ownerCanBeRemovedFromManagers.value());
    }
    return model;
}



ContainerPolicy Factory::parsePolicyServerObject(const Poco::Dynamic::Var& serverPolicyObject) {
    if (serverPolicyObject.isEmpty()) {
        return {};
    }
    Poco::JSON::Object::Ptr obj = serverPolicyObject.extract<Poco::JSON::Object::Ptr>();
    ContainerPolicy result {};
    result.get = Factory::getValueOrNullopt<std::string>(obj, "get");
    result.update = Factory::getValueOrNullopt<std::string>(obj, "update");
    result.delete_ = Factory::getValueOrNullopt<std::string>(obj, "delete");
    result.updatePolicy = Factory::getValueOrNullopt<std::string>(obj, "updatePolicy");
    result.updaterCanBeRemovedFromManagers = Factory::getValueOrNullopt<std::string>(obj, "updaterCanBeRemovedFromManagers");
    result.ownerCanBeRemovedFromManagers = Factory::getValueOrNullopt<std::string>(obj, "ownerCanBeRemovedFromManagers");

    if (obj->isObject("item")) {
        auto itemObj = obj->getObject("item");
        ItemPolicy itemResult {};
        itemResult.get = Factory::getValueOrNullopt<std::string>(itemObj, "get");
        itemResult.listMy = Factory::getValueOrNullopt<std::string>(itemObj, "listMy");
        itemResult.listAll = Factory::getValueOrNullopt<std::string>(itemObj, "listAll");
        itemResult.create = Factory::getValueOrNullopt<std::string>(itemObj, "create");
        itemResult.update = Factory::getValueOrNullopt<std::string>(itemObj, "update");
        itemResult.delete_ = Factory::getValueOrNullopt<std::string>(itemObj, "delete");
        result.item = itemResult;
    }        
    return result;
}

ContainerPolicyWithoutItem Factory::parsePolicyServerObjectWithoutItem(const Poco::Dynamic::Var& serverPolicyObject) {
    if (serverPolicyObject.isEmpty()) {
        return {};
    }
    Poco::JSON::Object::Ptr obj = serverPolicyObject.extract<Poco::JSON::Object::Ptr>();
    ContainerPolicyWithoutItem result {};
    result.get = Factory::getValueOrNullopt<std::string>(obj, "get");
    result.update = Factory::getValueOrNullopt<std::string>(obj, "update");
    result.delete_ = Factory::getValueOrNullopt<std::string>(obj, "delete");
    result.updatePolicy = Factory::getValueOrNullopt<std::string>(obj, "updatePolicy");
    result.updaterCanBeRemovedFromManagers = Factory::getValueOrNullopt<std::string>(obj, "updaterCanBeRemovedFromManagers");
    result.ownerCanBeRemovedFromManagers = Factory::getValueOrNullopt<std::string>(obj, "ownerCanBeRemovedFromManagers");        
    return result;
}
